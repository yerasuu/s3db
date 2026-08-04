# `s3db`: base de datos tipada y cifrada sobre storage S3-compatible

> Documento tecnico de la crate `crates/s3db`. Complementa (no reemplaza)
> `crates/s3db/README.md`, que es la referencia de API con ejemplos de uso.
> Aca el foco es como esta armada por dentro y por que, no como se usa.

## Contexto

Extraida de gitquarry: lo que hoy es `crates/s3db` empezo siendo plumbing
especifico de gitquarry (`storage::*`, `crypto::*`). Al auditarlo resulto
que ninguna de esas piezas dependia realmente de nada de gitquarry — el
input es un `Backend`, una passphrase, y JSON entrando y saliendo. Se
extrajo tal cual a una crate propia (`Cargo.toml` raiz, `[workspace]
members = ["crates/s3db", "crates/s3db-macros"]`).

Objetivo de diseno explicito: una unica forma de entrada/salida de datos
(un trait `Backend`, un formato de sellado cifrado) con el backend fisico
totalmente transparente por encima de esa linea — nada que este por encima
de `Backend` sabe (ni le importa) si esta hablando con S3, R2, Azure Blob,
GCS o un directorio local.

## Capas

```
┌─────────────────────────────────────────────────────────┐
│ App (gitquarry): auth::access, storage::settings, domain │
│   define sus propios tipos (User, Group, RepoConfig...), │
│   sus propios indices (PUBKEY_INDEX, REPO_NAME_INDEX...)  │
├─────────────────────────────────────────────────────────┤
│ s3db: Collection / Singleton / SecondaryIndex / txn::run  │
│   / RequestCache / #[derive(Entity)] (crate s3db-macros)  │
│   — primitivas genericas, no conocen ningun tipo de app   │
├─────────────────────────────────────────────────────────┤
│ s3db: json::{get_json, put_json} (cifra/descifra + CAS)   │
├─────────────────────────────────────────────────────────┤
│ s3db: trait Backend (get/put_cas/delete/list_prefix/      │
│   put_stream/get_stream)                                  │
├─────────────────────────────────────────────────────────┤
│ Drivers: S3Backend / AzureBackend / GcsBackend /          │
│   LocalBackend (S3Backend tambien sirve R2 via new_r2)    │
└─────────────────────────────────────────────────────────┘
```

Cada capa solo conoce la de abajo. La app nunca llama `Backend` directo
(verificado: cero llamadas a `.get`/`.put_cas`/etc fuera de
`auth::access`/`storage::settings`/`domain::*`) — todo pasa por las
primitivas tipadas.

## El trait `Backend`: la unica superficie que un driver implementa

```rust
#[async_trait::async_trait]
pub trait Backend: Send + Sync + std::fmt::Debug {
    async fn get(&self, key: &str) -> Result<(Vec<u8>, Option<String>)>;
    async fn put_cas(&self, key: &str, body: Vec<u8>, expected_etag: Option<&str>) -> Result<Cas>;
    async fn delete(&self, key: &str);
    async fn delete_many(&self, keys: &[String]) -> Result<()>;
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, u64)>>;
    async fn put_stream(&self, key: &str, source: &Path) -> Result<()>;
    async fn get_stream(&self, key: &str, dest: &Path) -> Result<()>;
}
```

Deliberadamente chico: sin presign, sin multipart, sin byte-range, sin
ACLs — surgio de auditar cada llamada S3 que gitquarry realmente hace, no
de anticipar necesidades futuras.

La garantia que importa de verdad es `put_cas`: `expected_etag: None`
significa "debe no existir todavia"; cualquier otro valor es
compare-and-swap real. Un driver sin soporte nativo de escritura
condicional (ej. un filesystem compartido) tiene que *fingir* CAS real
igual — no best-effort — porque todo lo que se construye encima
(reclamos de indice, transacciones multi-key, versionado) asume que esa
garantia nunca falla silenciosamente.

`delete`/`delete_many` son best-effort a proposito: nunca se usan para
algo de lo que dependa la logica de negocio (para eso esta `put_cas`), asi
que un fallo ahi nunca se propaga.

## Cifrado: obligatorio, sin opt-out

- **Algoritmo**: XChaCha20Poly1305 (nonce de 24 bytes, vs 12 del
  ChaCha20Poly1305 comun — margen mas grande para no reusar nonce con
  claves de larga vida).
- **KDF**: Argon2id, parametros fijos (perfil bajo-memoria de OWASP: 19
  MiB / 2 iteraciones / 1 thread), no configurables. Un salt aleatorio de
  16 bytes (`SALT_LEN`) por bucket.
- **AAD = key**: `Cipher::seal(aad, plaintext)`/`open(aad, sealed)` atan
  el ciphertext a `aad` como associated data del AEAD. Todo caller pasa la
  propia key S3 del objeto como `aad` — si alguien copia el ciphertext de
  una key a otra (bug o storage provider comprometido), el `open` con el
  `aad` de la key nueva falla la autenticacion. Formato sellado:
  `nonce(24) || ciphertext+tag`.
- **Streaming** (`seal_stream`/`open_stream`, para `put_stream`/
  `get_stream`): chunks de 4 MiB, cada uno con su propio nonce y un AAD
  que ata `aad` base + largo total declarado + indice del chunk — asi
  reordenar, truncar o duplicar chunks es detectable, no silenciosamente
  aceptado.
- **Bootstrap** (`bootstrap::get_or_create_cipher`): en el primer uso del
  bucket, genera el salt y lo guarda **sin cifrar, a proposito** en
  `.conf/encryption.json`, junto a un verificador sellado. En arranques
  siguientes, deriva la key desde `passphrase` y abre ese verificador —
  una passphrase incorrecta falla ahi mismo, como un error claro de
  arranque, en vez de manifestarse como fallos de deserializacion
  dispersos mas adelante en la app.

No existe modo "sin cifrar" en ningun punto: todo objeto que un driver
escribe en el bucket (salvo `.conf/encryption.json` mismo) pasa por
`seal`/`open`.

## Modelo de datos: un objeto por entidad, nunca un blob unico

Tres primitivas, todas construidas sobre `json::{get_json, put_json}`:

**`Collection`** — CRUD tipado sobre un conjunto de objetos que comparten
prefijo: `{prefix}/{name}{suffix}` (suffix default `.json`). `get`
devuelve `None` si no existe (no `T::default()` — el llamador no tiene que
recordar la convencion de `get_json` a mano). `put`/`put_versioned` son
CAS; `put_versioned` archiva el valor anterior bajo su propio etag antes
de pisarlo (`{prefix}/.history/{name}/{etag}.json`). `list_all`/`find_all`
son fan-out concurrente sobre todo el prefijo — full scan, solo para
vistas admin o colecciones chicas, nunca para lookups de request normal.

**`Singleton`** — mismo shape, una key fija sin `name` (ej.
`.conf/global.json`).

**`SecondaryIndex`** — un puntero de busqueda: `{root}/{kind}/{segment
(raw)}.json -> T`. `Segment::Raw` para un nombre ya seguro como componente
de path; `Segment::Base64` para bytes arbitrarios (huella de clave,
email) que pueden traer `/`. Reemplaza el patron que cada indice
(pubkey, email, namespace, uid inverso, nombre de repo...) hacia a mano
antes: su propio armado de key, su propia decision de encoding, su propia
estrategia de conflicto. Tres estrategias de claim:
- `claim_once`: un solo intento CAS, sin reintento — correcto cuando el
  espacio de keys no puede colisionar de verdad (un uid random) o el
  primero en llegar simplemente gana (reserva de namespace).
- `claim_best_effort`: fire-and-forget, errores tragados — para hints de
  lookup inverso cuya correctitud nunca depende de que el write aterrice.
- `claim_self_healing`: en conflicto, relee el puntero existente; si ya
  apunta al mismo valor es un reintento idempotente; si no, un callback
  `is_genuine` decide si el reclamo existente sigue vivo (rechazar) o esta
  obsoleto (reclamar con un CAS mas usando el etag recien leido).

## Transacciones multi-key create-only (`txn`)

`txn::run(backend, cipher, ops: Vec<TxnOp>)` empaqueta varios `create`
(nunca update) en una unidad todo-o-nada, sin necesitar protocolo de
lock/liveness: cada op es un `put_cas` con `expected_etag: None`, asi que
la propia key destino ES el lock. Flujo:

1. Ordena las ops por key (orden determinista, evita ciclos entre
   transacciones que compiten por las mismas keys).
2. Escribe un registro `Preparing` en `.conf/txn/<txn_id>.json`.
3. Aplica cada op. Un conflicto cuyo contenido existente coincide con lo
   que esta op iba a escribir se trata como "ya es mio" (reintento tras un
   crash a mitad de camino) y sigue. Un conflicto genuino aborta y hace
   rollback de todo lo ya aplicado.
4. CAS del registro a `Committed`, despues borra el registro.

`txn::recover_stale(backend, cipher, max_age)` — corrido al arrancar el
server — barre registros `.conf/txn/` todavia `Preparing` mas viejos que
`max_age`, los pasa a `Aborting` (le saca la propiedad a cualquier
`run` que siga vivo) y hace rollback. Asi una transaccion que crasheo a
mitad de camino no deja keys huerfanas para siempre.

## `RequestCache`: cache de una sola request, nunca de proceso

Decorator sobre `Backend` que cachea resultados de `get()` durante la vida
de una request/conexion — nunca mas alla, porque gitquarry corre varias
instancias de server contra el mismo bucket y un permiso cacheado stale
no puede sobrevivir a su revocacion. `put_cas`/`delete`/`delete_many`
invalidan la key tocada sin importar el resultado (incluso un
`Cas::Conflict`, porque el valor guardado puede haber cambiado igual).
`list_prefix`/`put_stream`/`get_stream` pasan derecho, sin cachear.

## `#[derive(Entity)]`: mismo modelo, sin repetir el boilerplate

Cada entidad escrita a mano (`User`, `Group`, `RepoConfig`) termina
escribiendo lo mismo: un `Collection` const, un `SecondaryIndex` const por
campo de busqueda, un struct puntero chiquito, y el trio claim/resolve/
release. La crate hermana `s3db-macros` (re-exportada como
`s3db::Entity`) genera exactamente eso a partir de atributos
(`#[entity(collection = "...")]`, `#[entity(key)]`,
`#[entity(index)]`) — sigue bajando a las mismas llamadas de `Collection`/
`SecondaryIndex` de siempre, no hay motor de queries nuevo ni magia de ORM
por debajo. No reemplaza `auth::access::User`/`Group` (siguen a mano,
migrarlos es un cambio aparte); esta pensado para entidades nuevas.

## Por que esto evita "problemas de gestion de datos"

- **Una sola forma de escribir**: no hay un segundo camino que arme keys a
  mano o cifre distinto — todo entra por `json::put_json`, asi que un bug
  de cifrado o de key-building se arregla en un solo lugar, no N veces.
- **CAS real en todos lados**: nada en la app hace read-modify-write sin
  etag — cada `put` de `Collection`/`Singleton`/`SecondaryIndex` exige
  `expected_etag` explicito, asi que una condicion de carrera nunca pisa
  silenciosamente un write concurrente.
- **Nunca un blob unico por tipo de dato**: cada usuario/grupo/repo/config
  es su propio objeto S3 (`.conf/users/<name>.json`, no
  `.conf/users.json`) — un solo write nunca puede corromper o bloquear a
  todos los demas del mismo tipo, y el costo de una escritura no crece con
  la cantidad de entidades.
- **Transacciones para lo que de verdad necesita atomicidad**: reservar
  namespace + reclamar pubkey/email + escribir el objeto de usuario son 3+
  keys que tienen que aterrizar todas juntas o ninguna — antes se hacia con
  rollback manual llamada por llamada; `txn::run` lo colapsa a una lista de
  ops.
- **Un solo backend abstraido**: cambiar de proveedor (S3 -> Azure, por
  ejemplo) no puede introducir un bug de "este proveedor guarda distinto"
  porque ningun codigo por encima de `Backend` sabe que proveedor es.

## Mapa de archivos

- `crates/s3db/src/backend.rs`: trait `Backend`, `Cas`, `build_backend`.
- `crates/s3db/src/s3.rs` / `azure.rs` / `gcs.rs` / `local.rs`: los 4
  drivers (S3 sirve tambien R2 via `S3Backend::new_r2`).
- `crates/s3db/src/config.rs`: `BackendConfig` (enum tageada por
  `driver`) y los params de cada uno.
- `crates/s3db/src/cipher.rs`: `Cipher`, seal/open, seal/open_stream.
- `crates/s3db/src/bootstrap.rs`: `get_or_create_cipher`, verificador de
  passphrase al arrancar.
- `crates/s3db/src/json.rs`: primitiva cruda cifrada (`get_json`/
  `put_json`) sobre la que todo lo demas se apoya.
- `crates/s3db/src/collection.rs`: `Collection`, `Singleton`.
- `crates/s3db/src/index.rs`: `SecondaryIndex`, `Segment`.
- `crates/s3db/src/txn.rs`: `TxnOp`, `run`, `recover_stale`.
- `crates/s3db/src/request_cache.rs`: `RequestCache`.
- `crates/s3db-macros/src/lib.rs`: `#[derive(Entity)]`.
- `crates/s3db/README.md`: referencia de API con ejemplos — leer ese en
  vez de este documento para "como uso tal cosa".
