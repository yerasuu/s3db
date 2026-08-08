# Rediseño: `s3db` como motor LSM sobre object storage (S3-only, un binario)

> **Diseño, todavía no implementado.** Este documento describe el plan tal
> como quedó acordado, no código existente. Reemplaza la versión anterior
> de este archivo (documento-suelto + índices por tipo, fases 1-5) — esa
> versión quedaba parchando el layout físico actual sin arreglar su techo
> real. Ver `git log` para confirmar si alguna fase ya aterrizó antes de
> asumir que sigue pendiente.
>
> Restricción que se mantiene, sin negociar: **solo object storage
> S3-compatible como primitivo, sin daemon de coordinación, un binario**
> (heredado de gitquarry, donde nació el crate). Nada acá agrega un proceso
> nuevo, un puerto nuevo, ni un protocolo de consenso.
>
> La sección de cifrado más abajo (opcional, algoritmo elegible/
> expansible) es política de este proyecto, ya independiente: un
> consumidor puede seguir exigiendo cifrado obligatorio por su cuenta
> (gitquarry lo hace), pero eso es decisión suya, no del motor.

## Diagnóstico raíz: por qué el diseño actual no llega a "full DB"

El documento anterior asumía que el problema era de *API* (falta rango,
falta tipo libre, falta join) y proponía resolverlo capa por capa arriba
del modelo actual. Pero el modelo actual tiene un problema de *layout
físico* que ninguna API nueva arregla:

- **1 registro = 1 objeto S3 = 1 request.** `Collection::put`/`get` hacen
  un `put_cas`/`get` por entidad. Con miles de writes/seg eso choca
  directo contra el techo de partición de S3 ya documentado en
  `docs/s3db.md` (~3,500 PUT/s, ~5,500 GET/s por rango de prefijo).
  `KeyEntropy::HashPrefix` reparte el hot-spot entre más particiones, pero
  no cambia que siga siendo 1 request por fila — sube el techo, no cambia
  la pendiente.
- **`SecondaryIndex` es un puntero exact-match**, no una estructura
  ordenada real. Un rango ("edad > 30") con `Segment::OrderedInt` (lo que
  proponía el documento anterior) devolvería keys ordenadas, sí, pero
  cada resultado sigue siendo un objeto individual — un scan de 10,000
  filas sigue siendo 10,000 `GET`s, no una lectura contigua.
- **CAS protege un objeto, nunca da una vista barata de "todo lo
  reciente".** No hay estructura donde leer 10,000 filas cueste menos que
  10,000 requests, porque nunca se agrupan físicamente.

Ningún ajuste de *tipo* o de *índice* resuelve esto — es una limitación
de cómo se agrupan los bytes en objetos, no de qué API se expone encima.
La solución real es la que ya usan los sistemas que resuelven este mismo
problema (motor de datos real sobre object storage puro, sin servidor de
coordinación): **SlateDB, WarpStream (Kafka sobre S3), Turbopuffer, el
storage layer de Neon, el formato de tabla Iceberg/Delta Lake** — todos
convergen en el mismo patrón cuando el sustrato es "objeto inmutable +
list + CAS". No es un diseño nuevo inventado acá, es el patrón que ya
ganó en la industria para este problema exacto.

## Arquitectura: LSM-tree con manifest CAS-controlado

**1. WAL local** (proceso, disco o memoria del propio binario). Cada
write entra acá primero — ack rápido al caller sin tocar S3 por write
individual. Reemplaza el `wal.rs` actual (que hoy es solo intención de
escritura para diagnóstico) por su rol real: buffer de durabilidad local
antes del flush.

**2. Memtable** — `BTreeMap<Key, Row>` en memoria, acumula writes desde
el último flush. Da orden real sin ningún request de red.

**3. Flush → SSTable inmutable en S3.** Al cruzar un umbral (tamaño o
tiempo), la memtable completa se serializa como **un solo objeto S3**,
formato columnar por bloques:

```rust
struct SSTable {
    blocks: Vec<Block>,        // filas ordenadas por key, agrupadas
    block_index: Vec<(Key, Key, u64, u32)>, // (min, max, offset, len) por bloque
    bloom: BloomFilter,        // descarta la tabla entera sin leer nada
}
```

Un flush de 10,000 filas = **1 PUT**, no 10,000. Esto es lo que rompe el
techo de partición: el volumen de requests deja de escalar con el número
de filas y pasa a escalar con el número de flushes.

**4. Manifest** (`{root}/MANIFEST.json`, CAS) — lista de SSTables
vigentes con su rango `(min_key, max_key)` y nivel de compactación.
Fuente única de verdad de qué existe; se actualiza con `put_cas` igual
que hoy — single-writer por manifest, mismo principio ya aceptado (sin
consenso multi-writer, ver sección final).

**5. Compactor — implementado, tiered completo, no leveled.** Cada
llamada mergea *todas* las SSTables de la tabla en una sola (o en cero, si
todo terminó tombstoned), nunca un subconjunto — eso es lo que permite
purgar tombstones sin ventana de retención: si el merge cubre todo el
manifest no queda nada más viejo sin mergear que un tombstone todavía
necesite tapar. Reemplaza `gc.rs`/`maintenance.rs` para tablas LSM.
`should_compact`/`compact` en `crates/s3db/src/lsm/compactor.rs`, invocado
explícitamente por quien llame (mismo patrón que `MaintenanceScanner`), no
un task en background dentro del crate.

**6. Lectura.**
- *Point lookup*: bloom filter por SSTable descarta las que no contienen
  la key sin abrirlas; binary search en `block_index`; **un `GET` con
  `Range` header** trae solo el bloque relevante, no el objeto entero.
- *Range scan*: merge-iterator sobre los SSTables cuyo rango se solapa
  con la query — ya están ordenados por construcción, es un scan
  contiguo real, no N gets.

**Cambio de trait necesario — implementado.** `Backend::get_range(key,
offset, len) -> Result<Vec<u8>>` ya está en los 5 drivers (`Range` header
en S3/R2/GCS/Azure, `seek`+`read_exact` en `Files`, slice en memoria en
`Redb`) más cada decorator (`Cached`/`Metered`/`Retry`/`Throttled`/
`RequestCache`).

**Corrección de diseño encontrada al implementar fase 2**: este documento
no decía cómo cifrado y lectura parcial conviven, y la respuesta obvia
("sellar el objeto entero, como todo lo demás") es criptográficamente
incompatible con `get_range` — un AEAD no se puede descifrar/autenticar
por partes, hace falta el ciphertext completo para verificar el tag. La
solución: cada bloque y el footer se sellan por separado
(`Cipher::seal`/`open` con su propio nonce+tag), AAD =
`{sstable_key}#block{idx}` / `{sstable_key}#footer` — así un
`get_range` trae una unidad AEAD completa y autoverificable, nunca un
fragmento de una más grande. Documentado en `crates/s3db/src/lsm/sstable.rs`.

## Tipos de dato — resueltos por el formato de bloque, no por un enum ad-hoc

Cada `Block` tiene columnas tipadas (mismo principio que Arrow/Parquet,
versión mínima): `Int64`, `Float64`, `Text`, `Bytes`, `Timestamp`,
`Bool`, `Array<T>`, y `Json` como escape hatch para schema no declarado.
Min/max por bloque (ya en `block_index`) habilita poda real de I/O:
`WHERE age > 30` salta bloques enteros sin leerlos, no solo evita
deserializar filas que no matchean.

## Multi-sitio — routing a nivel de manifest, no de objeto individual

Cada tabla es un manifest + su propio conjunto de SSTables, en un backend
elegido explícitamente:

```rust
pub struct TableLocation {
    backend_id: &'static str,   // clave en un BackendRegistry, default "primary"
    root: String,               // prefijo/bucket lógico de esa tabla
}
```

Más natural que en el diseño anterior porque el manifest ya es la unidad
que responde "quién es dueño de qué" — routear ahí es routear en el
mismo lugar donde ya vive la fuente de verdad, no una capa nueva
paralela.

## Cifrado: opcional (on por defecto), algoritmo elegible y expansible

> **Implementado.** Esta sección se conserva como el diseño acordado; lo
> que aterrizó difiere en dos detalles que el diseño no había fijado, y
> ambos están documentados en `crates/s3db/README.md`: el byte de header
> se reparte en nibbles (algoritmo arriba, compresión abajo) en vez de ser
> dos bytes, y el campo de nonce queda fijo en 24 bytes para que el header
> conserve su offset. Además `open` rechaza cruzar los modos (un `Cipher`
> con cifrado activo no acepta un objeto marcado "sin cifrar", ni al
> revés) — sin eso, `Disabled` sería un downgrade attack contra cualquier
> deployment cifrado.

`s3db-crypto::Cipher` era un único algoritmo fijo — `struct
Cipher(XChaCha20Poly1305)`, sin variantes, cifrado obligatorio sin
opt-out (herencia de gitquarry, ver disclaimer arriba). Dos cambios sobre
esa base, reusando el mecanismo que el propio
`Cipher::seal` ya tiene para esto exacto: el **header byte bound-into-AAD**
que solo describía compresión (`compression_header`) se generaliza a
describir también el algoritmo:

```rust
pub enum CipherAlgorithm {
    XChaCha20Poly1305, // = 0x00, default, comportamiento actual sin cambios
    Aes256Gcm,          // = 0x01
    // variantes nuevas se agregan al final, nunca se renumeran ni se borran
}

pub enum EncryptionMode {
    Enabled { algorithm: CipherAlgorithm }, // default: XChaCha20Poly1305
    Disabled,                                // opt-out explícito, no default
}
```

`seal` escribe el byte de algoritmo (o un byte reservado "sin cifrar" si
`Disabled`) junto al de compresión, ambos bound-into-AAD igual que hoy —
mismo argumento que ya está escrito para compresión: "sin esto, un
storage provider malicioso podría flipear el header sin que `open` lo
note". `open` lee el byte y despacha al algoritmo correcto — un bucket
puede tener objetos sellados con distintos algoritmos a la vez (mismo
principio que `CompressionStrategy` ya permite hoy por objeto), lo que
habilita **rotar el algoritmo default sin tener que re-sellar todo el
bucket de una vez** — mismo patrón gradual que `KeyRotationWorker` ya
usa para rotar passphrases.

**Expansible de verdad**: agregar `CipherAlgorithm::Nuevo` es un campo de
enum más + un brazo de `match` en `seal`/`open` — ningún objeto viejo se
rompe (su byte de header sigue apuntando a su algoritmo original), y
ningún caller que no pida el nuevo algoritmo lo ve nunca.

**Opcional, on por defecto**: `EncryptionMode::Enabled` es el default —
un caller tiene que pasar `Disabled`
explícitamente (mismo espíritu que "config explícita, no inferencia" del
resto del crate) para apagarlo. Con `Disabled`, `seal`/`open` se vuelven
passthrough (header marca "sin cifrar" para que un lector no adivine),
sin AEAD, sin Argon2id, sin passphrase requerida.

**Qué NO cambia**: el bootstrap de encryption (`bootstrap.rs`, verificador
temprano de passphrase) sigue igual cuando `Enabled` — nada de esto
debilita el caso por-defecto, solo agrega la puerta de salida explícita
que gitquarry mismo nunca quiso tener.

## Qué se mantiene fuera de alcance (declarado, no prometido de más)

- **Sin transacciones multi-tabla ACID cross-manifest.** Cada manifest
  su propio CAS, sin 2PC entre manifests distintos.
- **Sin multi-writer concurrente por tabla.** Single-writer por manifest
  — mismo motivo que siempre: replicación/consenso real necesita
  coordinación que S3 no da, y agregar un daemon de consenso viola la
  restricción de este documento (un binario, sin proceso extra).
- **El cómputo de queries (joins, agregación) sigue del lado del
  proceso que lee**, no un motor distribuido. La diferencia con el
  documento anterior es que ahora el I/O de base es real (scan contiguo,
  poda por min/max, bloom filter) — el cuello de botella deja de ser "un
  request por fila" y pasa a ser cómputo local, que es barato y sí escala
  con más CPU/RAM del proceso.

## Migración: no reemplaza `Collection<T: Entity>` para todo

Las colecciones actuales (usuarios, grupos, peers, configs — miles de
entidades, no millones, acceso por key exacta) siguen con el modelo
documento-suelto: no tienen el problema que este rediseño resuelve, y
migrarlas sería reescritura sin beneficio (contra "no speculative
abstractions"). El motor LSM es un **modo de storage nuevo, opt-in por
tabla** — se usa para lo que sí necesita volumen + rango + tipo (logs de
auditoría, métricas, futuros issues/PRs a escala del roadmap de forge).
`Collection`/`SecondaryIndex` actuales no se tocan.

## Fases de implementación

| Fase | Qué construye | Reemplaza |
|---|---|---|
| 1 ✅ | WAL + memtable + flush a SSTable (sin compactar) | Bootstrap del motor, nada existente |
| 2 ✅ | Manifest CAS + lectura (bloom + block index + `get_range`) | — |
| 3 ✅ | Compactor (merge + purga de tombstones) | `gc.rs`/`maintenance.rs`, para tablas LSM |
| 4 | Formato de bloque columnar tipado + schema declarado | — |
| 5 | Range scan + índice secundario (segundo LSM ordenado por otra key) | — |
| 6 | `TableLocation`/`BackendRegistry` (routing multi-backend) | — |
| 7 ✅ | `CipherAlgorithm`/`EncryptionMode` (header de algoritmo, opt-out) | `s3db-crypto::Cipher` gana enum, sin romper objetos ya sellados |
| 8 (opcional) | Query builder mínimo sobre 1-5 | — |

**Fase 1 implementada** en `crates/s3db/src/lsm/` (`Wal`, `Memtable`,
`sstable::build`, `Table::{open,put,delete,flush}`). Solo escritura, como
dice la tabla — `Table` no tiene todavía forma de leer una fila ya
flusheada (`get_unflushed` deliberadamente no se llama `get`: solo ve lo
que sigue en memtable). El formato de objeto SSTable (bloques +
block_index + bloom + footer) ya quedó completo desde esta fase porque
separarlo de fase 2 hubiera significado rehacerlo; lo que fase 2 agrega es
`Backend::get_range` en los 5 drivers, el manifest, y el camino de lectura
que usa bloom+block_index para no traer el objeto entero.

**Orden real:** 1 → 2 son bloque mínimo funcional (sin esto no hay motor).
3 puede esperar (SSTables sin compactar funcionan, solo degradan lectura
con el tiempo). 4 y 5 son el valor central del pedido original (tipo +
rango) y dependen de 1-2. 6 es independiente, se puede hacer en paralelo
a 3-5. 7 es independiente de todo lo anterior (toca `s3db-crypto`, no el
motor LSM) — se puede hacer en cualquier momento, incluso primero. 8 al
final, condicionado a uso real.
