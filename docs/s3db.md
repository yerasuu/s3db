# `s3db`: Correcciones a la extensión de escala (>1M entidades)

> Fe de erratas y rediseño puntual sobre `s3db: Extensión para Alto
> Rendimiento a Escala`. Presupone lectura de ese documento y del
> documento base de `crates/s3db`. No repite lo que ya funciona ahí —
> cada sección de acá corresponde a una falla concreta encontrada en
> auditoría, con el mecanismo de corrección, no solo la advertencia.
>
> Convención: cada sección dice **Falla**, **Por qué pasa**, **Corrección**.
> Al final, tabla de qué archivo/struct cambia.

## 1. Tombstone + delete best-effort dejan objetos huérfanos para siempre

**Falla.** `Collection::delete` escribe el tombstone (CAS create-only) y
después borra el objeto original con `delete()` best-effort. Si ese
segundo paso falla (red, throttling, lo que sea), nadie se entera: el
tombstone existe, `get()` ya devuelve `None`, y el objeto real queda
vivo en el bucket para siempre. `GcScheduler` solo purga tombstones
*expirados*, nunca reintenta el `delete` que nunca aterrizó.

**Por qué pasa.** El diseño original trata `delete` como best-effort
*a propósito*, porque nada de negocio depende de que aterrice. Eso deja
de ser cierto en cuanto el tombstone empieza a depender de que el
`delete` subyacente también aterrice — se introdujo una dependencia
nueva sin ajustar la garantía vieja.

**Corrección.** El tombstone pasa a tener un campo de estado explícito,
y el borrado real del objeto deja de ser "fire and forget":

```rust
#[derive(Serialize, Deserialize)]
pub struct Tombstone {
    deleted_at: DateTime<Utc>,
    deleted_by: Option<String>,
    expires_at: Option<DateTime<Utc>>,
    purge_state: PurgeState,
}

pub enum PurgeState {
    /// Tombstone escrito, delete del objeto original todavía no confirmado.
    Pending,
    /// delete() del objeto original confirmó (o el objeto ya no existía).
    Purged,
}
```

`Collection::delete(key)`:
1. Escribe tombstone con `purge_state: Pending`.
2. Llama `delete(key)` sobre el objeto original.
3. Si el paso 2 confirma (o el backend reporta 404, que cuenta como éxito),
   hace `put_cas` del tombstone a `purge_state: Purged`. Si el paso 2
   falla, el tombstone se queda en `Pending` — y eso ahora es una señal,
   no un agujero.

`GcScheduler` agrega una tarea nueva, **antes** de la purga de
tombstones expirados: escanear tombstones en `Pending` más viejos que
un umbral corto (ej. 60s) y reintentar `delete()` sobre el objeto
original. Un tombstone solo se considera candidato a purga por edad
(`tombstone_max_age`) si ya está en `Purged`. Así "huérfano por delete
fallido" y "huérfano por vejez" son dos colas distintas con dos
políticas distintas, y ninguna se confunde con la otra.

## 2. `restore()` no limpia el tombstone → objeto restaurado sigue invisible

**Falla.** `restore(key)` re-escribe el objeto desde `.history/`, pero
`get(key)` sigue mirando el tombstone primero. Si el tombstone no se
borra, el objeto recién restaurado sigue devolviendo `None` para
siempre. `restore()` "funciona" y el resultado observable es idéntico a
que no haya hecho nada.

**Corrección.** `restore()` es su propia operación CAS de dos escrituras
en el orden correcto — primero el dato, después la remoción de la
barrera que lo oculta:

```rust
impl<T: Entity> Collection<T> {
    async fn restore(&self, key: &str) -> Result<()> {
        let tombstone = self.read_tombstone(key).await?
            .ok_or(Error::NothingToRestore)?;
        let version = self.latest_history_version(key).await?
            .ok_or(Error::HistoryExpired)?;

        self.write_object_for_restore(key, version).await?; // ver §3
        self.delete_tombstone(key).await?; // best-effort explícito, logueado
        Ok(())
    }
}
```

`delete_tombstone` sigue siendo best-effort (mismo argumento que
siempre: borrar un tombstone no es de lo que depende la corrección de
datos), pero ahora **se llama explícitamente como parte de
`restore()`**, no se asume. Y como el objeto ya está escrito antes de
tocar el tombstone, un fallo en el segundo paso deja el peor caso en
"objeto restaurado pero oculto" — recuperable reintentando el borrado
del tombstone — nunca en "objeto perdido".

## 3. `restore()` choca contra objetos huérfanos del bug §1

**Falla.** `restore()` hace `put_cas` con `expected_etag: None` porque
asume que el objeto no existe. Si el bug de §1 ya ocurrió (delete
original nunca confirmó), la key sigue ocupada y el `restore` explota
con conflicto CAS — justo en el caso en que más se necesita.

**Corrección.** Con §1 resuelto, este caso ya no debería darse en la
operación normal (no se marca `Purged` sin confirmar el delete real).
Pero `restore()` no debe asumirlo por las dudas — cambia a
`cas_with_reread` en vez de CAS ciego:

```rust
async fn write_object_for_restore<T: Entity>(&self, key: &str, version: T) -> Result<()> {
    // Si la key sigue ocupada (objeto huérfano preexistente al bug §1,
    // por datos ya corridos antes de este fix), gana la versión restaurada,
    // no falla el restore.
    cas_with_reread(&self.backend, &self.cipher, key, |_current| version.clone(), 3).await?;
    Ok(())
}
```

Esto también hace `restore()` idempotente ante reintentos del propio
caller, que antes hubiera fallado en el segundo intento por el mismo
motivo (objeto ya escrito por el primer intento).

## 4. `ShardedIndex`: split-brain de claims durante rebalanceo

**Falla.** Con `HashPrefix(n)`, durante la ventana de migración
`resolve` busca en shard viejo y nuevo (bien, para lectura). Pero
`claim_once` no dice a qué shard escribe un *writer*. Si dos procesos
corren con `n` distinto (uno todavía no recogió el `n` nuevo), cada
uno calcula un shard distinto para el mismo segmento y ambos ganan su
propio CAS local — el mismo segmento queda reclamado dos veces, en
shards distintos, sin que ningún CAS lo haya detectado.

**Por qué pasa.** CAS protege dentro de una key; nunca protegió "este
segmento lógico en general" — esa garantía dependía de que segmento →
shard fuera una función pura y estable, y durante rebalanceo deja de
serlo.

**Corrección.** El `EncryptionConfig`-style pattern se repite acá:
versión explícita del esquema de sharding, no inferencia por `n` local.

```rust
#[derive(Serialize, Deserialize)]
pub struct ShardEpoch {
    epoch: u32,
    prefix_bits: u8,       // n actual
    prev_prefix_bits: Option<u8>, // n anterior, Some solo durante migración
}
```

`ShardEpoch` vive en `{root}/{kind}/.shard-epoch.json`, leído (con
cache corto, no por-request) antes de cada `claim_once`. Mientras
`prev_prefix_bits` sea `Some`, **todo `claim_once` escribe en el shard
viejo, nunca en el nuevo** — el rebalanceo migra datos, no acepta
escrituras nuevas en destino todavía. Solo cuando el
`RebalanceWorker` termina de copiar un shard viejo completo a sus dos
hijos, hace un `put_cas` que fija `prev_prefix_bits: None` para ese
shard (el epoch es por-shard-viejo, no global, para no bloquear todo
el índice mientras un solo shard rebalancea). Recién ahí los writers
empiezan a escribir en el shard nuevo. `resolve` sigue mirando ambos
mientras el shard viejo no fue formalmente marcado migrado y purgado.

Esto convierte "todos calculan el shard con el `n` que tengan a mano"
(inseguro) en "todos preguntan a una fuente única cuál es el shard de
escritura vigente" (serializado por el propio `ShardEpoch`, que es una
key con su propio CAS).

## 5. Orden de decoradores: `Throttled` afuera de `Retry` retiene permits durante el backoff

**Falla.** `MeteredBackend → ThrottledBackend → RetryBackend → ...`
significa que el semáforo de `ThrottledBackend` se adquiere *antes* de
que `RetryBackend` intente la llamada, y se libera recién cuando
`RetryBackend` termina — incluyendo todo el backoff exponencial con
jitter de los reintentos internos. Bajo carga alta, un reintento que
tarda 2-3 segundos en agotar su política mantiene un permit
bloqueado todo ese tiempo, reduciendo la concurrencia real disponible
justo cuando más se necesita, y empujando al circuit breaker a abrir
por presión que él mismo generó.

**Corrección.** Invertir el orden: el retry va *afuera* del throttle.
Cada intento individual (incluyendo los reintentos) adquiere y libera
su propio permit; el semáforo nunca queda ocupado durante el sleep del
backoff.

```
MeteredBackend
  └── RetryBackend          (orquesta reintentos, backoff entre intentos)
        └── ThrottledBackend  (permit solo durante la llamada de red real)
              └── CompressingBackend
                    └── CachedBackend
                          └── S3Backend
```

Efecto práctico: cada intento de un reintento compite por un permit
nuevo, igual que cualquier otra request — que es lo correcto, porque
un reintento no debería tener prioridad ni exención respecto al
tráfico nuevo. El circuit breaker (que sigue viviendo en
`ThrottledBackend`) ahora mide la tasa de error de llamadas de red
reales, no la tasa de error inflada por reintentos que además
retenían recursos compartidos.

## 6. Ambigüedad de dónde vive la caché (dejar resuelto, sin el debate en el texto)

**Falla.** El documento de escala dejaba el razonamiento de la decisión
sin depurar ("espera, no, cachea a nivel Backend..."), lo cual es
inofensivo para el comportamiento pero mala señal para quien lo lea
después: parece una decisión tomada en caliente y no revisada.

**Corrección (fijada, sin ambigüedad).** `CachedBackend` cachea
exclusivamente bytes crudos + etag, a nivel `Backend`, **después** del
driver físico y **antes** de que `json.rs` descifre/deserialice. Razón
fijada, no debatida: una caché a nivel `Backend` es reutilizable entre
cualquier `Collection`/`SecondaryIndex` que toque la misma key S3 —
cachear post-descifrado duplicaría el mismo objeto deserializado N
veces si N tipos lo leen a través de wrappers distintos, y además
pondría material descifrado en memoria por más tiempo del necesario.
La entrada de caché nunca contiene plaintext.

## 7. `WalWriter`: mencionado en el diagrama, nunca especificado

**Falla.** El documento de escala lo pone en el diagrama de capas y en
el mapa de archivos (`wal.rs`) sin una sola línea de qué hace, cuándo
escribe, ni cómo se relaciona con el registro `Preparing` que ya
escribe `txn::run`. Queda como una promesa de diseño sin diseño.

**Corrección — especificación mínima.** `WalWriter` no reemplaza el
registro de transacción de `txn::run` (ese ya cumple su función:
recuperación de transacciones create-only interrumpidas). `WalWriter`
cubre un caso que `txn::run` no cubre: **intención de escritura previa
a un `put_cas` individual fuera de una transacción**, para que
`GcScheduler`/`HealthProbe` puedan distinguir "esta escritura nunca se
intentó" de "esta escritura se intentó y no sabemos si aterrizó"
(ej. proceso murió justo alrededor del `put_cas`, antes de que el
caller reciba la respuesta).

```rust
pub struct WalEntry {
    op_id: Uuid,
    key: String,
    intent_hash: String,      // hash del body que se iba a escribir
    started_at: DateTime<Utc>,
}
```

Se escribe en `.conf/wal/<op_id>.json` (create-only, best-effort en la
escritura del WAL mismo — si ni el WAL logra escribirse, no hay
ambigüedad que resolver, la operación simplemente no empezó), justo
antes del `put_cas` real, y se borra (best-effort) apenas el `put_cas`
confirma, sea éxito o conflicto genuino. `recover_stale`-equivalente
para WAL: al arrancar, entradas más viejas que un umbral se resuelven
comparando `intent_hash` contra el objeto actual en esa key — si
coincide, la escritura aterrizó, se borra la entrada; si no coincide y
no hay CAS conflict pendiente, se asume que no aterrizó y se descarta
sin reintentar (reintentar una escritura vieja sin que el caller
original lo pida es peligroso — puede pisar algo más reciente). El WAL
es una herramienta de *diagnóstico y limpieza de ambigüedad*, no un
mecanismo de garantía de entrega.

## 8. `GcScheduler` puede podar `.history/` que un `ReadSnapshot` activo necesita

**Falla.** `ReadSnapshot` depende de que la versión necesaria siga en
`.history/`. `GcScheduler` poda por edad/cantidad sin saber si hay un
snapshot vivo que la referencia. Un snapshot de larga duración puede
morir con `SnapshotExpired` exactamente cuando el GC corre por
casualidad al medio.

**Corrección — lease explícito, corto y con expiración forzada.**

```rust
pub struct SnapshotLease {
    snapshot_id: Uuid,
    timestamp: DateTime<Utc>,
    max_duration: Duration,   // tope duro, ej. 5 minutos
}
```

Al crear un `ReadSnapshot`, se registra un `SnapshotLease` en
`.conf/snapshots/<snapshot_id>.json` con `max_duration` acotado (no se
soportan snapshots "de larga duración" — para eso ya existe
`BackupManager`, ver §12). `GcScheduler`, antes de podar una versión de
`.history/`, chequea si su timestamp cae dentro de la ventana de algún
lease vigente (`now - lease.timestamp < lease.max_duration`); si sí, la
salta esta pasada y la reintenta en la próxima corrida del GC. El
lease se borra al cerrar el `ReadSnapshot` (o expira solo por
`max_duration`, así un snapshot nunca-cerrado no bloquea el GC para
siempre — el tope duro es no negociable, no configurable por caller).
Esto no vuelve el snapshot "de larga duración" — sigue siendo
best-effort acotado — pero elimina la carrera silenciosa entre dos
mecanismos que antes no se hablaban.

## 9. Compresión duplicada en dos capas distintas del stack

**Falla.** Objetos sueltos comprimen vía `CompressingBackend`
(decorator de `Backend`). Streaming comprime dentro de
`seal_stream`/`open_stream` en `cipher.rs`. Dos implementaciones, dos
lugares, mismo problema — exactamente lo que el documento base dice
evitar ("una sola forma de escribir, un bug se arregla en un solo
lugar").

**Corrección.** La compresión se mueve a una sola responsabilidad:
**vive en `cipher.rs`, no en un decorator de `Backend`**, para objetos
sueltos y streaming por igual. `seal`/`open` (no solo las variantes
`_stream`) reciben la `CompressionStrategy` como parámetro y aplican el
mismo formato de header ya definido para streaming
(`nonce || compression_header(1) || ciphertext+tag`, header dentro del
AAD). `CompressingBackend` se elimina del stack de decorators de
`Backend` — la compresión deja de ser una capa de storage y pasa a ser
un parámetro del sellado, igual que el AAD-por-key ya lo es. Una sola
implementación, un solo formato, para el caso chico y el streaming.

```rust
impl Cipher {
    pub fn seal(&self, aad: &[u8], plaintext: &[u8], compression: CompressionStrategy) -> Vec<u8>;
    pub fn open(&self, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>>; // header determina si descomprime
}
```

`build_resilient_backend` pierde una capa (`CompressingBackend` ya no
existe ahí):

```
MeteredBackend
  └── RetryBackend
        └── ThrottledBackend
              └── CachedBackend
                    └── S3Backend
```

## 10. Firma inconsistente de `delete` vs `delete_many` en el trait `Backend`

**Falla.** `delete` no devuelve `Result`, `delete_many` sí — ambos
documentados como best-effort. La asimetría no tiene justificación
escrita: o el `Result` de `delete_many` transporta información que
`delete` también debería transportar (conteo de éxitos parciales para
métricas/GC), o es ruido de tipo que no se usa.

**Corrección.** Se unifica: ambos devuelven `Result<DeleteOutcome>`,
donde `DeleteOutcome` es informativo, no propagable como fallo de
negocio (mantiene la garantía original de que nada crítico depende de
esto):

```rust
pub struct DeleteOutcome {
    attempted: usize,
    confirmed: usize, // 404 o 200 de delete cuentan como confirmado
}

async fn delete(&self, key: &str) -> Result<DeleteOutcome>;
async fn delete_many(&self, keys: &[String]) -> Result<DeleteOutcome>;
```

Esto es lo que necesita §1 para que el reintento de purga huérfana
tenga una señal real de éxito en vez de adivinar, y unifica el
contrato del trait sin cambiar la filosofía best-effort.

## 11. Costo de Argon2id se paga por cada key retirada en cada `open` fallido

**Falla.** El dual-read de rotación de claves prueba la key actual y,
si falla, prueba las retiradas de más reciente a más vieja — pero
Argon2id es deliberadamente caro (eso es lo que lo hace seguro). Si el
`KeyRotationWorker` se atrasa y acumulan varias keys retiradas vivas,
abrir un objeto viejo paga N derivaciones Argon2id en cascada. El
propio mecanismo de seguridad se vuelve el cuello de botella de
latencia para los datos que más necesitan rotarse.

**Corrección — separar derivación de key de intento de apertura.**
Las keys derivadas (no las passphrases, las keys ya derivadas de
Argon2id) se mantienen en memoria de proceso mientras la
`KeyMaterial` correspondiente siga en `EncryptionConfig` (retirada o
no) — la derivación Argon2id se paga **una sola vez por key, al
arrancar el proceso o al detectar una key nueva**, no una vez por
intento de `open`:

```rust
pub struct KeyRing {
    derived: HashMap<String, DerivedKey>, // key_id -> key ya derivada
}
```

`Cipher::open` ya no deriva nada — solo prueba desencriptar contra las
`DerivedKey` ya calculadas en el `KeyRing`, en orden de más reciente a
más vieja, lo cual es barato (verificación AEAD, no KDF). Esto además
acota el problema real: si `KeyRotationWorker` se atrasa demasiado, el
costo que crece es memoria del `KeyRing` (una entrada más por key
retirada, barato) y no latencia por objeto (que ahora es plana sin
importar cuántas keys retiradas existan). La política de purga de
keys sin objetos restantes sigue igual que en el documento de escala.

## 12. `BackupManager` no declara su propia inconsistencia de punto-en-el-tiempo

**Falla.** `ReadSnapshot` es honesto sobre ser "best-effort, no MVCC
real". `BackupManager` hace `scroll` sobre cada colección mientras el
bucket sigue recibiendo escrituras, y no dice en ningún lado que el
resultado es una mezcla de estados de distintos instantes — no un
punto-en-el-tiempo real. Doble estándar de honestidad dentro del mismo
documento.

**Corrección — declarar la limitación y acotar su impacto.**
`BackupManager` agrega un campo explícito al manifest de cada backup:

```rust
pub struct BackupManifest {
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    consistency: BackupConsistency,
}

pub enum BackupConsistency {
    /// scroll corrido sin coordinación con escrituras concurrentes.
    /// Cada entidad individual es consistente (se lee completa),
    /// pero el conjunto puede mezclar estados de instantes distintos
    /// dentro de [started_at, finished_at].
    FuzzySnapshot,
}
```

No se resuelve el problema de fondo (eso requeriría algo tipo MVCC real,
explícitamente rechazado en la decision matrix del documento de
escala por complejidad injustificada) — se documenta la garantía real
en el propio artefacto, para que `verify_backup` y cualquier proceso
de restore sepan qué están mirando: un backup lógico es fiel entidad
por entidad, no un corte atómico del bucket completo. Restore
punto-en-el-tiempo (que combina backup + `.history/`) hereda esta
misma advertencia y debería documentarla en su resultado, no asumir
más precisión de la que el mecanismo puede dar.

---

## Tabla resumen: qué cambia dónde

| # | Falla | Archivo/struct afectado | Tipo de cambio |
|---|-------|--------------------------|----------------|
| 1 | Objeto huérfano tras delete fallido | `collection.rs`: `Tombstone.purge_state`; `gc.rs`: tarea nueva | Campo nuevo + tarea GC nueva |
| 2 | `restore()` no limpia tombstone | `collection.rs`: `restore()` | Reordenar pasos, agregar borrado |
| 3 | `restore()` choca con huérfanos | `collection.rs`: `write_object_for_restore` | CAS ciego → `cas_with_reread` |
| 4 | Split-brain de shard durante rebalanceo | `sharded_index.rs`: `ShardEpoch` | Struct nuevo + gating de escritura |
| 5 | Throttle afuera de retry retiene permits | `resilience/mod.rs`: orden de composición | Reordenar decorators |
| 6 | Ambigüedad de dónde cachea | `cache.rs` (sin cambio de código, solo doc) | Aclaración de diseño |
| 7 | `WalWriter` sin especificar | `wal.rs`: `WalEntry` + recuperación | Especificación nueva |
| 8 | GC poda historial que un snapshot usa | `snapshot.rs`: `SnapshotLease`; `gc.rs`: chequeo de lease | Struct nuevo + gating de GC |
| 9 | Compresión duplicada | `compress.rs` eliminado; `cipher.rs`: `seal`/`open` con `CompressionStrategy` | Mover capa, eliminar decorator |
| 10 | `delete`/`delete_many` firma inconsistente | `backend.rs`: trait `Backend` | Cambio de firma (breaking, pero interno) |
| 11 | Argon2id repetido por key retirada | `key_rotation.rs`: `KeyRing` | Cache de keys derivadas en proceso |
| 12 | Backup sin declarar inconsistencia | `backup.rs`: `BackupManifest.consistency` | Campo nuevo, honestidad explícita |

Ninguna corrección rompe la API pública de `s3db` core (Collection /
Singleton / SecondaryIndex / txn::run) — todas viven en `s3db-scale` o
`s3db-resilience`, consistente con la premisa de ambos documentos
anteriores: el core no se toca, las capas de escala se ajustan encima.

## 13. `BatchLoader::load_many` — el tipo de retorno no puede expresar lo que el texto promete

**Falla.** El texto dice "keys inexistentes devuelven `Ok(None)` (no
errores), igual que `Collection::get`". Pero la firma declarada es:

```rust
async fn load_many<T: Entity>(
    &self,
    keys: impl IntoIterator<Item = String>,
) -> HashMap<String, Result<T>>;
```

`Result<T>` no tiene forma de contener `None` — o hay un `T`, o hay un
`Error`. Si de verdad se implementa como está tipado, una key
inexistente *tiene* que ser un `Err(...)`, lo cual contradice
directamente el comportamiento prometido y rompe la paridad con
`Collection::get` que el propio texto reclama.

**Corrección.** El tipo se corrige para que exprese lo que se quiere
decir, ya no una promesa que el compilador no puede cumplir:

```rust
async fn load_many<T: Entity>(
    &self,
    keys: impl IntoIterator<Item = String>,
) -> HashMap<String, Result<Option<T>>>;
```

`Ok(None)` = key no existe (paridad real con `Collection::get`).
`Ok(Some(t))` = encontrado. `Err(...)` = fallo real de red/backend tras
agotar la política de la capa de resiliencia — reservado para lo que
de verdad es excepcional, no para "no está".

## 14. `HealthProbe` puede reportar `ready` usando una respuesta cacheada, no una real

**Falla.** `ready()` hace `GET` a `.conf/health-ping.json` para
verificar que el backend es alcanzable. Pero si ese `GET` pasa por el
mismo stack decorado que el resto del tráfico (`CachedBackend` incluido,
ver orden de composición), y esa key tiene una entrada todavía vigente
en la LRU, el health check puede devolver éxito leyendo de memoria
mientras S3 está efectivamente caído. El probe termina midiendo "¿tengo
una copia vieja en RAM?", no "¿puedo hablarle a S3 ahora mismo?" —
exactamente lo opuesto de lo que un health check para un orchestrator
necesita.

**Corrección.** `HealthProbe` no usa el `Backend` decorado de la app.
Recibe una referencia separada, sin `CachedBackend` en el camino (el
resto de la pila de resiliencia — retry, throttle, métricas — sí puede
quedarse, porque no oculta el estado real del backend, solo lo
reintenta o lo mide):

```rust
pub struct HealthProbe {
    // Construido explícitamente SIN CachedBackend en la composición,
    // aunque comparta el mismo S3Backend/driver de fondo.
    probe_backend: Arc<dyn Backend>,
    cipher_ok: AtomicBool,
    recovery_done: AtomicBool,
}
```

Regla fijada: cualquier decorator que pueda devolver una respuesta sin
tocar la red (`CachedBackend`, y a futuro cualquier otro con la misma
propiedad) queda excluido de la composición usada por `HealthProbe`,
por definición del propósito del probe.

## 15. `WriteCoalescer`: qué pasa en conflicto CAS al momento del flush no está especificado

**Falla.** El coalescer debouncea escrituras a la misma key y ejecuta
"solo la última" tras `flush_interval`. No se dice qué pasa si, al
momento de aplicar ese `put_cas` final, otra instancia (o esta misma,
fuera del coalescer) ya escribió esa key en el medio — el `expected_etag`
capturado cuando arrancó el debounce ya no es válido. Sin
especificación, el camino más probable en una implementación ingenua es
"el conflicto se trata como error y el write coalesceado se descarta en
silencio" — pérdida de escritura silenciosa, justo el tipo de bug que
el resto del documento (CAS real en todos lados, `cas_with_reread`)
existe para evitar.

**Corrección.** El flush del coalescer nunca hace CAS ciego contra un
etag capturado al inicio del debounce — usa `cas_with_reread`, igual
que cualquier otro read-modify-write bajo concurrencia:

```rust
impl<B: Backend> WriteCoalescer<B> {
    async fn flush(&self, key: &str) -> Result<Cas> {
        let pending = self.pending.remove(key)?; // último valor pedido
        cas_with_reread(
            &self.inner,
            &self.cipher,
            key,
            move |_current| pending.value.clone(),
            /* max_attempts */ 3,
        ).await
    }
}
```

Esto no cambia el trade-off ya documentado (latencia artificial de
`flush_interval` a cambio de menos requests) — solo cierra el hueco de
que ese ahorro de requests no debe costar la garantía de que ningún
write se pierda sin que alguien se entere.

## Tabla resumen (extensión)

| # | Falla | Sección del doc de escala que tocaba | Archivo/struct afectado |
|---|-------|----------------------------------------|--------------------------|
| 13 | `BatchLoader` retorno no expresa "no existe" | §6 | `batch_loader.rs`: firma de `load_many` |
| 14 | Health check puede leer de caché | §11 | `health.rs`: `HealthProbe.probe_backend` |
| 15 | Coalescer puede perder writes en conflicto | §17 | `coalescer.rs`: `flush()` |

## 16. Migración, GC y rotación de claves son tres escaneos completos de background independientes

**Falla.** `MigrationRunner`, `GcScheduler` y `KeyRotationWorker` cada
uno hace su propio `scroll` sobre el bucket completo, en su propio
horario, sin coordinación entre sí. Con >1M entidades, eso es
potencialmente 3-4 pasadas completas por el mismo conjunto de objetos
en paralelo (más la posible pasada de `BackupManager`), cada una
compitiendo por el mismo presupuesto de `ThrottledBackend` — no rompen
nada (el throttle las protege de saturar S3), pero desperdician
round-trips: cada pasada vuelve a leer objetos que las otras pasadas
ya leyeron en la misma ventana de tiempo, solo para chequear una
condición distinta (`_v` desactualizado / tombstone expirado / key de
cifrado retirada).

**Corrección.** Se consolida en un único `MaintenanceScanner` que hace
`scroll` una vez por objeto y evalúa las tres condiciones en el mismo
paso, delegando la acción correspondiente:

```rust
pub struct MaintenanceScanner {
    migration: Option<MigrationConfig>,
    gc: Option<GcConfig>,
    key_rotation: Option<KeyRotationConfig>,
}

impl MaintenanceScanner {
    async fn scan_object<T: Entity>(&self, key: &str, raw: &(Vec<u8>, Option<String>)) -> Result<()> {
        // Un solo get_json ya trae _v y permite detectar la key de cifrado usada.
        if self.needs_migration(raw) { self.migrate(key, raw).await?; }
        if self.needs_reencryption(raw) { self.reencrypt(key, raw).await?; }
        if self.is_expired_tombstone(key) { self.purge(key).await?; }
        Ok(())
    }
}
```

`MigrationRunner`, `GcScheduler` y `KeyRotationWorker` pasan a ser
*políticas* inyectadas en un único scanner, no tres procesos de
background separados. Cada uno conserva su propio intervalo de
habilitación (se puede seguir corriendo GC más seguido que migración,
por ejemplo, vía flags por-pasada), pero la lectura del objeto se paga
una sola vez por ciclo, no N veces.

## 17. `ChangePublisher` no especifica granularidad dentro de `txn::run` — eventos parciales de una transacción no comprometida

**Falla.** El documento dice que se publica un evento "después de cada
`put_cas` exitoso" — pero `txn::run` aplica varias `put_cas` una por
una antes de llegar a `Committed`. Si se publica un evento por cada op
individual a medida que se aplica, un consumidor (search index,
webhook, réplica) puede ver 2 de 3 escrituras de una transacción que
todavía no comprometió — y si la tercera choca genuinamente y la
transacción hace rollback de las dos anteriores, el consumidor ya
recibió eventos de escrituras que fueron revertidas, sin ningún evento
compensatorio que se lo diga.

**Corrección.** `txn::run` acumula los `ChangeEvent` de sus ops
internamente y los publica **todos juntos, una sola vez, después de
que el registro pase a `Committed`** — nunca durante la fase de
aplicación:

```rust
impl TxnRun {
    async fn run(&self, ops: Vec<TxnOp>) -> Result<TxnOutcome> {
        let mut pending_events = Vec::new();
        for op in &ordered_ops {
            let outcome = self.apply(op).await?;
            pending_events.push(ChangeEvent::from(op, outcome));
        }
        self.mark_committed().await?;
        for event in pending_events {
            self.publisher.published(event).await; // fire-and-forget, ya comprometido
        }
        Ok(TxnOutcome::Committed)
    }
}
```

Si la transacción aborta y hace rollback, `pending_events` simplemente
se descarta — nunca se publicó nada, porque nunca se comprometió nada.
Fuera de una transacción (un `put_cas` suelto vía `Collection`), el
comportamiento documentado originalmente no cambia.

## 18. `RequestCache` (core) y `CachedBackend` (escala) nunca se especifican juntos

**Falla.** El documento base define `RequestCache` como decorator de
`Backend`, vida de una sola request. El documento de escala define
`CachedBackend`, LRU cross-request, también decorator de `Backend`.
Ningún documento dice qué pasa cuando **ambos** están montados a la
vez — que es el caso normal en producción a escala, no la excepción.
Sin especificar el orden, alguien podría montarlos con `CachedBackend`
por fuera de `RequestCache`, lo cual haría que la LRU cross-request
nunca se entere de los hits servidos por la caché de request (no
aprenden entre sí, pero tampoco hay bug de datos) — o peor, invertir
el orden de invalidación y dejar una ventana donde una request
posterior en la misma conexión ve un valor que ya fue invalidado por
`CachedBackend` pero no por `RequestCache`.

**Corrección.** Orden fijado explícitamente en la composición general:

```
App
  └── RequestCache        (vida de una request; siempre la capa más externa)
        └── MeteredBackend
              └── RetryBackend
                    └── ThrottledBackend
                          └── CachedBackend   (LRU cross-request)
                                └── S3Backend
```

`RequestCache` va afuera de todo lo demás porque su invalidación
(en cualquier `put_cas`/`delete` de esa misma request) debe ver el
resultado final después de que la escritura ya atravesó retry/throttle
— invalidar antes de saber si la escritura realmente aterrizó
reintroduciría el mismo problema que ya se evita en `CachedBackend`
(invalidar sin importar el resultado, incluyendo conflictos, pero
**después** de que la operación real ya corrió). Un `GET` que golpea
`RequestCache` nunca llega a tocar la LRU de `CachedBackend` — se
acepta esa pérdida de "warming" cross-request a cambio de mantener las
dos garantías de invalidación independientes y sin ambigüedad de
orden.

## 19. `BackupManager` no dice si respalda tombstones — se pierde el rastro de soft-delete al restaurar

**Falla.** El backup lógico hace `scroll` "sobre cada colección" y
serializa el estado vivo. No se especifica si eso incluye los objetos
en `{prefix}/.deleted/` (tombstones). Si no los incluye, un restore
completo desde backup pierde toda la información de qué fue borrado y
cuándo — el propósito entero de haber introducido tombstones (auditoría
y recuperación de borrados) desaparece en el momento exacto de un
disaster recovery, que es cuando más se necesita esa historia.

**Corrección.** `BackupManager` respalda tombstones como una colección
más, explícitamente, no como un efecto secundario de "escanear todo":

```rust
pub struct BackupManifest {
    started_at: DateTime<Utc>,
    finished_at: DateTime<Utc>,
    consistency: BackupConsistency,
    includes_tombstones: bool, // siempre true salvo opt-out explícito
}
```

`scroll` para backup recorre tanto `{prefix}/{name}.json` como
`{prefix}/.deleted/{name}.json` del mismo prefijo, y el restore
reconstruye ambos: objetos vivos como objetos vivos, tombstones como
tombstones (no como si nunca hubieran existido). Un backup que omite
tombstones debe declararlo explícitamente en el manifest
(`includes_tombstones: false`) para que nadie asuma auditoría completa
donde no la hay.

## 20. Autocrítica: mi propia corrección de `KeyRing` (§11) introduce un trade-off de seguridad no declarado

**Falla.** La corrección de §11 mantiene las keys ya derivadas
(post-Argon2id) en memoria de proceso mientras la `KeyMaterial`
correspondiente exista en `EncryptionConfig`, para no repetir la
derivación cara en cada `open`. Eso es correcto para el problema de
latencia que resuelve, pero tiene un costo que el texto original de
§11 no declaró: material de key derivado vive más tiempo en RAM
(potencialmente horas o días, hasta que `KeyRotationWorker` purgue la
key retirada), ampliando la superficie de exposición ante un volcado de
memoria del proceso, comparado con derivar bajo demanda y descartar
inmediatamente.

**Corrección.** Se declara el trade-off explícitamente y se acota:

- `KeyRing` solo mantiene en memoria las keys **derivadas**, nunca la
  `passphrase` original (eso ya era cierto, pero vale decirlo).
- Las entradas de `KeyRing` correspondientes a keys ya marcadas
  `retired_at` se eliminan de memoria tan pronto
  `KeyRotationWorker` confirma cero objetos restantes con esa key —
  no hay que esperar a que se borren de `EncryptionConfig` en disco;
  la purga de memoria puede (y debe) ser más agresiva que la purga de
  configuración.
- En perfiles de seguridad alta (a definir por la app vía config, no
  por default de la crate), `KeyRing` puede desactivarse y volver al
  comportamiento original de §11 sin el fix (derivar en cada intento),
  aceptando el costo de latencia a cambio de no mantener material
  derivado vivo más tiempo del estrictamente necesario para la
  operación en curso.

## 21. `ShardedIndex`: nadie decide cuándo empezar a rebalancear un shard

**Falla.** La corrección de §4 especifica *cómo* se rebalancea un shard
de forma segura (gating de escrituras vía `ShardEpoch`), pero ni ese
documento ni el original dicen *quién* decide que un shard concreto ya
creció demasiado y hay que arrancar la migración. Sin ese disparador,
el rebalanceo es un botón manual que alguien tiene que acordarse de
apretar — en la práctica, nunca se aprieta a tiempo, y el hot-spot que
el sharding existe para evitar vuelve a aparecer dentro de un shard
individual que creció más de la cuenta.

**Corrección.** El tamaño por shard ya es observable vía
`MetricsRecorder` (`s3db_index_resolves_total` puede desagregarse por
shard). Se agrega una métrica dedicada, y el disparo pasa a ser
automático, no manual:

```rust
fn gauge(&self, name: &str, value: f64); // ya existe en MetricsRecorder

// Nueva métrica: s3db_shard_occupancy{index, shard} -> conteo aproximado
```

`RebalanceWorker` (parte de `s3db-scale`, corriendo dentro del
`MaintenanceScanner` unificado de §16) consulta esta métrica
periódicamente; si un shard supera un umbral configurable
(`shard_rebalance_threshold`, default 2x el tamaño esperado con
`shard_count` actual — ej. >8,000 entradas para el default de 256
shards / 1M entidades), dispara automáticamente el bump de
`prefix_bits` para ese shard vía `ShardEpoch`, sin intervención manual.
El umbral es deliberadamente conservador (2x, no 1x) para no
rebalancear por ruido de conteo aproximado.

## Tabla resumen (segunda extensión)

| # | Falla | Alcance | Archivo/struct afectado |
|---|-------|---------|--------------------------|
| 16 | Migración/GC/rotación son 3 scans completos independientes | Eficiencia operativa | `maintenance.rs`: `MaintenanceScanner` (nuevo, consolida los 3) |
| 17 | Eventos parciales de transacciones no comprometidas | Corrección de datos aguas abajo | `txn.rs`: `run()` acumula y publica al final |
| 18 | Orden de `RequestCache` vs `CachedBackend` sin especificar | Corrección de datos / staleness | Diagrama de composición general |
| 19 | Backup no incluye tombstones | Completitud de disaster recovery | `backup.rs`: `BackupManifest.includes_tombstones` |
| 20 | Trade-off de seguridad no declarado en mi propio fix §11 | Seguridad | `key_rotation.rs`: `KeyRing`, purga agresiva + opt-out |
| 21 | Nadie dispara el rebalanceo de shard automáticamente | Operabilidad | `metrics.rs` + `sharded_index.rs`: `RebalanceWorker` |

# Ajustes de diseño para el perfil "objetos chicos, sin archivos grandes"

> A diferencia de las secciones anteriores (fallas de corrección), lo
> que sigue son oportunidades de diseño que solo tienen sentido dado un
> dato nuevo: el bucket nunca va a contener archivos grandes. Eso
> invalida el costo de mantener cierta infraestructura, y habilita
> optimizaciones de lectura que antes no valían la pena priorizar.

## 22. `put_stream`/`get_stream` son peso muerto garantizado — y dejan un hueco de memoria sin guardia

**Oportunidad.** Todo el mecanismo de streaming (chunks de 4 MiB, nonce
por chunk, AAD con índice de chunk) existe para un caso que, dado el
requisito nuevo, nunca va a ocurrir. Mantenerlo como parte obligatoria
del trait `Backend` no cuesta memoria en runtime si nunca se llama —
pero sí dejó un hueco real: **`json::put_json` nunca tuvo guardia de
tamaño**, porque el caso "objeto grande" tenía una válvula de escape
(`put_stream`) para cuando alguien se equivocara e intentara meter algo
grande por el camino no-streaming. Sin esa válvula mental, un bug de
aplicación (ej. serializar un campo que accidentalmente contiene un
blob) hoy balloonea memoria en `seal()` sin aviso, porque `seal` carga
todo el plaintext en RAM antes de cifrar.

**Ajuste.**

1. `put_stream`/`get_stream` pasan de obligatorios a un feature flag de
   compilación (`streaming`, off por default en este perfil). Los
   drivers que no lo activan devuelven `Error::NotSupported` en vez de
   implementar chunking que nunca se ejercita — menos superficie de
   código, menos rutas para auditar.
2. `json::put_json` agrega un guard explícito y barato, **antes** de
   serializar:

```rust
const MAX_OBJECT_BYTES: usize = 256 * 1024; // configurable, perfil "sin archivos grandes"

pub fn put_json<T: Serialize>(backend: &impl Backend, cipher: &Cipher, key: &str, value: &T) -> Result<Cas> {
    let plaintext = serde_json::to_vec(value)?;
    if plaintext.len() > MAX_OBJECT_BYTES {
        return Err(Error::ObjectTooLarge { key: key.to_string(), size: plaintext.len(), limit: MAX_OBJECT_BYTES });
    }
    // ... seal + put_cas como antes
}
```

Esto convierte "nunca va a haber archivos grandes" de supuesto
implícito a invariante garantizada — un bug de aplicación falla rápido
y con un error claro, en vez de manifestarse como presión de memoria
difusa bajo carga.

## 23. Compresión: dejar de decidir por objeto, decidir una vez por perfil

**Oportunidad.** `CompressionStrategy::Auto{threshold_bytes}` chequea
el tamaño de cada plaintext en cada escritura para decidir si vale la
pena comprimir. Con el perfil "objetos chicos garantizado", ese chequeo
casi nunca va a disparar compresión (la mayoría de las entidades JSON
de esta escala están muy por debajo de 5 KB) — el branch se paga en
cada escritura para un resultado que ya se sabe de antemano.

**Ajuste.** Para este perfil, `CompressionStrategy` se fija
estáticamente en `None` a nivel de configuración de despliegue, no se
evalúa por objeto. Se elimina el chequeo de tamaño del hot path de
escritura por completo (no hay branch, no hay intento de invocar
zstd/lz4). Si en el futuro aparece una colección con objetos
consistentemente grandes (dentro del límite de §22), se activa
compresión explícitamente para *esa* colección vía el mismo mecanismo
de configuración por-`Collection` que ya existe para caché — nunca
como decisión automática por tamaño individual.

## 24. Las keys de `Collection` no tienen entropía de partición — el mayor techo de velocidad de consulta que ningún documento anterior tocó

**Oportunidad — la más importante de esta tanda.** S3 (y compatibles)
particiona internamente por prefijo de key, y da más throughput
agregado cuantas más particiones distintas tocan las requests. Hoy,
`Collection` arma keys como `{prefix}/{name}{suffix}` —
`.conf/users/alice.json`, `.conf/users/bob.json`, etc. — todas bajo el
mismo prefijo lexicográfico `users/`. Con alto volumen de consultas
sobre una sola colección, **todas las requests caen en el mismo rango
de partición**, sin importar cuántas instancias de servidor corran en
paralelo — el límite de ~5,500 GET/sec o ~3,500 PUT/sec (ya
documentado en la extensión de escala) aplica a esa colección entera,
no se multiplica por instancia. Esto es exactamente el problema que
`ShardedIndex` ya resuelve para índices secundarios — pero nunca se
generalizó a `Collection`, que es donde vive el dato real.

**Ajuste.** Se agrega una opción de entropía de key a `Collection`,
reusando la misma idea de `ShardFn` que ya existe en `ShardedIndex`:

```rust
pub struct CollectionKeyStrategy {
    entropy: KeyEntropy,
}

pub enum KeyEntropy {
    /// Comportamiento actual: {prefix}/{name}.json
    None,
    /// {prefix}/{hash(name) mod n:04x}/{name}.json — mismo hash que
    /// ShardedIndex, spread de partición sin cambiar la API pública
    /// de Collection (get/put siguen recibiendo `name`, el hash es interno).
    HashPrefix { buckets: u32 },
}
```

Con `HashPrefix`, `{prefix}/users/{shard}/{name}.json` distribuye los
mismos usuarios entre N rangos de partición distintos, multiplicando el
throughput agregado disponible por el número de buckets — igual
principio que `ShardedIndex`, aplicado donde más impacta: el objeto
real, no solo el puntero. Opt-in por `Collection` (no rompe colecciones
existentes ya escritas sin entropía); migrar una colección existente a
`HashPrefix` requiere una pasada de reescritura, igual que cualquier
cambio de esquema de key — se apoya en el mismo `MaintenanceScanner`
de §16 para hacerlo en background sin scan dedicado nuevo.

## 25. Lookup por índice secundario cuesta dos round-trips — con objetos chicos, inline es más barato que doble GET

**Oportunidad.** `SecondaryIndex::resolve` hoy es: GET al puntero, y
si existe, GET al objeto. Dos round-trips de red por lookup — con
objetos grandes eso es insignificante comparado con la transferencia,
pero con objetos chicos y prioridad en velocidad de consulta, la
segunda round-trip es puro overhead de latencia de red (no de
transferencia, que es trivial para un objeto chico).

**Ajuste.** `SecondaryIndex` gana un modo opt-in `inline`, donde el
puntero carga una copia denormalizada del objeto completo (viable
justamente porque se garantiza que nunca es grande):

```rust
pub enum IndexMode<T> {
    /// Comportamiento actual: puntero + segundo GET.
    PointerOnly,
    /// El puntero incluye una copia del valor. resolve() es un solo GET.
    /// La copia se re-escribe en cada claim/update del índice, con el
    /// mismo etag del objeto real como versión — igual disciplina de
    /// invalidación que CachedBackend (staleness acotada, nunca silenciosa).
    Inline,
}
```

Costo: cada actualización del objeto debe también re-escribir su copia
en cada índice `Inline` que lo referencia (más escrituras, no más
lecturas) — trade-off correcto para el perfil declarado, donde se
prioriza velocidad de consulta y los objetos son chicos, así que
duplicar el contenido no pesa en memoria ni en storage de forma
significativa. `PointerOnly` sigue siendo el default; `Inline` se
activa por índice, solo donde el patrón de acceso es
lookup-dominante.

## 26. `CachedBackend`: contar bytes es contabilidad de más cuando se sabe que los objetos son chicos y uniformes

**Oportunidad.** `CacheConfig.max_bytes` obliga a sumar/restar el
tamaño de cada entrada en cada inserción y evicción — bookkeeping
correcto cuando el tamaño de los objetos es impredecible (podían ser
grandes). Con el perfil "sin archivos grandes", el tamaño por entrada
es chico y relativamente uniforme; contar bytes exactos ya no compra
nada que contar entradas no compre más barato.

**Ajuste.** Para este perfil, `CacheConfig` prioriza `max_entries`
sobre `max_bytes` (que pasa a ser un techo de seguridad opcional, no la
cuenta primaria de cada operación):

```rust
pub struct CacheConfig {
    max_entries: usize,       // cuenta primaria: O(1) por insert/evict
    max_bytes: Option<usize>, // techo de seguridad, chequeado solo si se supera max_entries
    ttl: Duration,
}
```

Memoria total queda acotada de forma predecible como
`max_entries × tamaño_típico`, sin pagar una suma/resta de tamaño en
cada operación de la LRU — menos trabajo por `get`/`put_cas`, que es
exactamente el hot path que se quiere rápido.

## 27. Revisitar §6: cachear el objeto ya descifrado y parseado, no los bytes crudos

**Oportunidad.** La decisión fijada en §6 (cachear bytes crudos,
post-driver, pre-descifrado) tenía sentido cuando el objetivo era
reusabilidad entre colecciones y minimizar tiempo de material
descifrado en memoria. Con el nuevo objetivo explícito de **velocidad
de consulta** y objetos garantizados chicos, ese diseño paga
descifrado (AEAD) + deserialización JSON en *cada* hit de caché,
cuando el resultado va a ser el mismo objeto una y otra vez mientras el
TTL esté vigente — costo de CPU repetido que se puede evitar.

**Ajuste.** Se agrega un modo opt-in por `Collection`,
`cache_typed`, que cachea el valor `T` ya descifrado y deserializado
(no los bytes crudos), a costa de perder la reusabilidad entre
colecciones distintas que compartan key S3 (caso raro en la práctica —
`Collection`/`SecondaryIndex` usan namespaces de key distintos por
diseño, así que la reusabilidad cruzada que motivó la decisión
original de §6 rara vez se ejerce de verdad):

```rust
let users = Collection::<User>::builder()
    .cache(CacheConfig { ttl: Duration::from_secs(60), mode: CacheMode::Typed, .. })
    .build(backend.clone());
```

`CacheMode::Raw` (comportamiento de §6) sigue siendo el default para
colecciones que sí comparten acceso a las mismas keys desde múltiples
tipos; `CacheMode::Typed` es la opción explícita cuando la prioridad es
velocidad de lectura pura y el objeto es de un solo tipo consumido
siempre de la misma forma — que es el caso común dado el perfil nuevo.

## 28. Pool de conexiones HTTP del driver: nunca especificado, y ahora es lo que domina la latencia

**Oportunidad.** Con objetos grandes, el tiempo de transferencia domina
la latencia de una request y el costo de establecer la conexión es
relativamente chico en comparación. Con objetos chicos, es al revés:
handshake TLS + setup de conexión puede ser la mayor parte del tiempo
de una request si no hay *keep-alive* real. Ningún documento anterior
menciona configuración de pool de conexiones del cliente HTTP
subyacente de `S3Backend`/`AzureBackend`/`GcsBackend`.

**Ajuste.** El pool de conexiones persistentes del cliente HTTP se
dimensiona explícitamente para igualar (no exceder) los límites de
`ThrottledBackend` (`max_concurrent_get` + `max_concurrent_put` +
`max_concurrent_list`), con keep-alive habilitado y timeout de
conexión idle generoso (varios minutos, no el default corto de muchos
clientes HTTP) — para que la concurrencia real disponible nunca esté
limitada por reestablecer conexiones que el propio `ThrottledBackend`
ya decidió que pueden estar en vuelo.

## 29. Concurrencia default de `scroll`/`BatchLoader` estaba calibrada para el caso general, no para este perfil

**Oportunidad.** `BatchLoader.max_batch` (default 100) y la
concurrencia de `scroll` fueron pensadas sin asumir tamaño de objeto —
conservadoras para no arriesgar memoria si los objetos resultaban
grandes. Con el tope de §22 (`MAX_OBJECT_BYTES`) garantizando un techo
por objeto, el presupuesto de memoria de `max_batch_buffer_mb` permite
calcular una concurrencia mucho más alta de forma segura:
`concurrencia_segura ≈ max_batch_buffer_mb / (MAX_OBJECT_BYTES en MB)`.

**Ajuste.** El default de `max_batch` y la concurrencia de `scroll`
dejan de ser una constante fija y pasan a derivarse del presupuesto de
memoria configurado y el tope de tamaño de objeto — más paralelismo
real de red sin arriesgar el presupuesto de memoria, que es
exactamente el punto de tener ambos números ya declarados por
separado en `MemoryBudget` y en el guard de §22.

## Tabla resumen (perfil de objetos chicos / alta velocidad)

| # | Oportunidad | Objetivo que sirve | Archivo/struct afectado |
|---|-------------|---------------------|--------------------------|
| 22 | Streaming feature-gated + guard de tamaño en `put_json` | Memoria baja, determinismo | `backend.rs` (feature flag), `json.rs`: `MAX_OBJECT_BYTES` |
| 23 | Compresión fija en `None` por perfil, sin chequeo por objeto | Velocidad (menos branches en write) | `cipher.rs`: config estática, no `Auto` |
| 24 | Entropía de key en `Collection` (generaliza `ShardFn`) | Velocidad de consulta agregada | `collection.rs`: `CollectionKeyStrategy` |
| 25 | Modo `Inline` en `SecondaryIndex` (un solo GET) | Velocidad de consulta por lookup | `index.rs`: `IndexMode::Inline` |
| 26 | Caché por conteo de entradas, no por bytes | Memoria baja + menos trabajo por op | `cache.rs`: `CacheConfig.max_entries` primario |
| 27 | Caché de objeto tipado (post-descifrado) opt-in | Velocidad (evita re-descifrar/re-parsear) | `cache.rs`: `CacheMode::Typed` |
| 28 | Pool de conexiones HTTP dimensionado explícitamente | Velocidad (evita handshake repetido) | driver `s3.rs`/`azure.rs`/`gcs.rs`: config de cliente |
| 29 | Concurrencia derivada del presupuesto de memoria, no constante fija | Velocidad + memoria acotada explícitamente | `batch_loader.rs`, `paginator.rs`: cálculo de concurrencia |

# Ajustes específicos: app en Rust, entidades como structs tipados

> El nombre de la crate (`s3db`) y el formato interno (`json::{get_json,
> put_json}`) llevan a asumir JSON como formato de datos. Pero dado que
> (a) la app es Rust y las entidades ya son structs con `serde`
> vía `#[derive(Entity)]`, y (b) todo objeto (salvo el bootstrap de
> cifrado) está *siempre* cifrado — el beneficio de "JSON es legible"
> nunca se ejerce en la práctica, porque nadie va a leer el ciphertext
> a mano de todos modos. Eso habilita cambios que antes no valían el
> costo de romper la legibilidad.

## 30. El body serializado no necesita ser JSON — nadie lo lee, siempre está cifrado

**Oportunidad.** `json::put_json`/`get_json` usan JSON como formato de
plaintext antes de sellar. Para structs Rust con `serde`, JSON paga:
nombres de campo como texto repetidos en cada objeto, escaping,
parseo basado en texto (más lento que un formato binario posicional o
autodescrito), y alocaciones de `String` para cada valor. Todo eso
tiene sentido cuando alguien puede necesitar inspeccionar el archivo
crudo — pero acá el archivo crudo *siempre* es ciphertext (excepto
`.conf/encryption.json`, que es la única excepción declarada y sigue
siendo JSON a propósito, porque ese sí se lee a mano en un incidente).
El resto del bucket nunca se beneficia de que el plaintext-antes-de-cifrar
haya sido JSON.

**Ajuste — con la salvedad de evolución de esquema.** Cambiar a un
formato binario de `serde` reduce CPU (parseo) y memoria (menos
alocaciones intermedias) en cada `get`/`put`. La elección concreta
importa por lo que ya existe en el documento de escala: el sistema de
migraciones (`#[entity(version = N)]`, `_v` embebido, migración lazy)
asume que el formato tolera campos agregados/quitados sin reescribir
todo a mano. Eso descarta `bincode`/`postcard` puros (posicionales,
frágiles ante cambios de struct) como reemplazo directo — la
recomendación es **MessagePack** (`rmp-serde`): binario, compacto,
rápido, y sigue siendo autodescrito por nombre de campo como JSON, así
que el mecanismo de migración existente no cambia de forma:

```rust
// json.rs pasa a mejor nombrado como `payload.rs`, pero mantiene la firma:
pub fn put_json<T: Serialize>(backend: &impl Backend, cipher: &Cipher, key: &str, value: &T) -> Result<Cas> {
    let plaintext = rmp_serde::to_vec_named(value)?; // en vez de serde_json::to_vec
    // ... seal + put_cas sin cambios
}

pub fn get_json<T: DeserializeOwned>(backend: &impl Backend, cipher: &Cipher, key: &str) -> Result<Option<T>> {
    // ... get + open sin cambios
    Ok(Some(rmp_serde::from_slice(&plaintext)?))
}
```

`.conf/encryption.json` y cualquier otro archivo pensado para
inspección humana en un incidente (ese es el único que existe hoy)
se queda en JSON explícitamente — la excepción ya está declarada en el
documento base y sigue siendo la correcta. Todo lo demás — que es
donde vive el volumen real de lecturas/escrituras — pasa a
MessagePack. Migrar el bucket existente de JSON a MessagePack es una
pasada de reescritura, igual que cualquier cambio de esquema: se apoya
en el `MaintenanceScanner` de §16 (que ya lee y re-escribe cada objeto)
en vez de ser un mecanismo nuevo.

## 31. Caché tipado (§27): devolver `Arc<T>`, no clonar el struct entero en cada hit

**Oportunidad.** §27 propuso cachear el valor `T` ya descifrado y
deserializado en vez de bytes crudos, para ahorrar CPU de
descifrado+parseo en cada hit. Tal como quedó planteado, cada `get`
que pega en la caché todavía tiene que devolver un `T` — si eso implica
`T: Clone` y clonar la entrada cacheada, se paga una copia completa del
struct (y de todo lo que contenga: `Vec`, `String`, etc.) en cada hit,
lo cual devuelve buena parte del costo que se quería evitar,
especialmente para structs con varios campos de texto.

**Ajuste.** La entrada de la caché tipada guarda `Arc<T>`, no `T`
directo. Un hit de caché es un `Arc::clone` (incremento de contador de
referencias, sin copiar el contenido):

```rust
pub struct TypedCacheEntry<T> {
    value: Arc<T>,
    etag: Option<String>,
    inserted_at: Instant,
}

impl<T: Entity> Collection<T> {
    async fn get(&self, name: &str) -> Result<Option<Arc<T>>> {
        // hit: Arc::clone barato; miss: descifra+parsea, envuelve en Arc, cachea
    }
}
```

Esto cambia la firma pública de `get()` para colecciones con
`cache_typed` habilitado (`Option<Arc<T>>` en vez de `Option<T>`) —
aceptable porque el caller casi siempre solo lee campos del valor, y
`Arc<T>` se desreferencia transparente. Colecciones sin caché tipada
mantienen `Option<T>` sin cambios.

## 32. Construcción de keys: cada `get`/`put` alloca un `String` nuevo para lo mismo, una y otra vez

**Oportunidad.** Cada llamada a `Collection::get`/`put` arma la key
con algo equivalente a
`format!("{prefix}/{name}{suffix}")` — una alocación de `String` nueva
por llamada, para un patrón que es el mismo en cada invocación de esa
`Collection` (solo cambia `name`). Con volumen alto de consultas, eso
es una alocación de heap evitable por request, en el hot path exacto
que se quiere rápido.

**Ajuste.** El macro `#[derive(Entity)]` genera un builder de key que
escribe directo a un buffer reusable en vez de `format!` + `String`
nuevo:

```rust
// Generado por #[derive(Entity)] para cada tipo:
impl User {
    #[inline]
    fn write_key(buf: &mut String, name: &str) {
        buf.clear();
        buf.push_str("users/");
        buf.push_str(name);
        buf.push_str(".json");
    }
}
```

`Collection<T>::get`/`put` reciben (o mantienen internamente, por
task/conexión) un buffer de `String` reusado entre llamadas —
evita la alocación repetida sin cambiar la API pública (el caller
sigue pasando `&str`, el manejo del buffer es interno).

## 33. `SecondaryIndex`/`Segment`: obligar a `String` cuando el campo indexado ya es un tipo con bytes naturales

**Oportunidad.** `Segment::Raw`/`Base64` operan sobre `String`. Pero
muchos campos que se indexan en la práctica ya son tipos Rust con una
representación de bytes natural y barata — `Uuid` (16 bytes), `u64`
(8 bytes), un hash de 32 bytes — y hoy hay que pasarlos por
`.to_string()` (o Base64-encodearlos) para poder usarlos como
`Segment`, pagando una conversión y una alocación de texto para un
valor que nunca necesitó ser texto.

**Ajuste.** `Segment` se generaliza sobre cualquier tipo que exponga
sus bytes de forma barata, con `Raw`/`Base64` quedando como los casos
particulares para cuando el campo indexado sí es naturalmente texto
(email, namespace):

```rust
pub trait IndexKey {
    fn key_bytes(&self) -> Cow<'_, [u8]>;
}

impl IndexKey for Uuid { fn key_bytes(&self) -> Cow<'_, [u8]> { Cow::Borrowed(self.as_bytes()) } }
impl IndexKey for u64  { fn key_bytes(&self) -> Cow<'_, [u8]> { Cow::Owned(self.to_be_bytes().to_vec()) } }
impl IndexKey for str  { fn key_bytes(&self) -> Cow<'_, [u8]> { Cow::Borrowed(self.as_bytes()) } }
```

`#[entity(index)]` sobre un campo `Uuid` o `u64` usa directamente su
`key_bytes()` (codificado a hex/base64 solo al armar la key final de
S3, que sí necesita ser texto por naturaleza del backend) — el punto
es que el campo tipado nunca pasa por una conversión a `String`
intermedia solo para satisfacer la API del índice.

## 34. Guía para quien define entidades: structs con muchos `String` cortos cuestan más de lo que parece

**Oportunidad.** No es un cambio de la crate sino una guía de uso: con
`#[derive(Entity)]` operando sobre structs definidos por la app
(`User`, `Group`, `RepoConfig`, etc.), cada campo `String` es una
alocación de heap separada. Un struct con 6-8 campos de texto corto
(nombres, emails, ids como texto) hace 6-8 alocaciones por instancia
deserializada — para objetos que se cachean en memoria (§27/§31) o se
mueven por `BatchLoader`, eso es fragmentación y overhead de alocador
que se nota a este volumen.

**Ajuste — recomendación documentada, no forzada por la crate.** Para
campos de texto corto y de tamaño acotado (nombres de usuario, IDs en
texto, slugs), se sugiere `compact_str::CompactString` en vez de
`String` en la definición del struct de entidad: inlinea strings de
hasta ~24 bytes sin alocar heap, y es *drop-in* compatible con
`serde`/`Deserialize` (implementa las mismas conversiones que
`String` para el caso común). Esto vive en el `README.md` de la crate
como guía de definición de entidades, no como un requisito — sigue
siendo `String` normal para campos donde el contenido puede ser largo
o impredecible (descripciones, texto libre).

## Tabla resumen (Rust + structs)

| # | Oportunidad | Objetivo que sirve | Archivo/struct afectado |
|---|-------------|---------------------|--------------------------|
| 30 | MessagePack en vez de JSON para el plaintext (bootstrap sigue en JSON) | Memoria + velocidad (parseo binario, sin perder migración) | `json.rs` → `payload.rs`: `put_json`/`get_json` |
| 31 | Caché tipada devuelve `Arc<T>`, no clona el struct | Velocidad (evita copia profunda por hit) | `cache.rs`: `TypedCacheEntry<T>` |
| 32 | Key-building sin `format!`/alocación nueva por llamada | Velocidad (menos allocs en hot path) | macro `s3db-macros`: `write_key` generado |
| 33 | `Segment`/`SecondaryIndex` acepta bytes tipados, no fuerza `String` | Velocidad (evita `.to_string()` de tipos ya tipados) | `index.rs`: trait `IndexKey` |
| 34 | Guía de `CompactString` para campos de texto corto en entidades | Memoria (menos heap-alloc por instancia) | `README.md`: guía de definición de entidades |