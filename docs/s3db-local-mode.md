# Modo local: motor real (`redb`), sin las restricciones de object storage

> **Diseño, todavía no implementado.** Complementa
> `docs/s3db-fulldb-roadmap.md` (LSM sobre object storage) — ese
> documento sigue siendo el diseño para backends S3-compatibles
> (`S3`/`R2`/`Azure`/`Gcs`). Este cubre el matiz concreto de `Local`:
> con libertad total en ese modo (una sola máquina, filesystem propio,
> sin billing por request, sin latencia de red), las restricciones que
> justifican el diseño LSM del otro documento simplemente no aplican.
> Ver `git log` para confirmar si alguna fase ya aterrizó.
>
> La sección de cifrado más abajo es política de este proyecto, ya
> independiente: un consumidor puede seguir exigiendo cifrado obligatorio
> por su cuenta (gitquarry lo hace), pero eso es decisión suya, no del
> motor.

## Restricción que se mantiene: mismo API público en ambos modos

Igual que hoy (`lib.rs`: "swapping drivers changes nothing above this
line"), `Collection<T>`/`SecondaryIndex`/`txn::run` no cambian de firma
según el backend. Código de aplicación no distingue si corre contra S3 o
contra `Local`. Lo que este documento agrega es una **capability
opcional** que solo `Local` implementa (ver más abajo) — el mínimo común
(CAS por key, transacción create-only) sigue garantizado en todos lados;
`Local` da más, nunca menos.

## Por qué modo local es un caso aparte (diagnóstico)

El diseño LSM del otro documento existe para resolver problemas
específicos de S3: costo por request, techo de partición, sin
transacción nativa multi-key, sin acceso aleatorio barato sin traer el
objeto completo. **Ninguno de esos problemas existe en un filesystem
local**: no hay billing por syscall, no hay RTT de red, y ya hay
primitivos reales de atomicidad (`fsync`, rename atómico, `flock`) — de
hecho `local.rs` ya los usa hoy para emular CAS a mano, sidecar por
sidecar.

Con libertad total, la respuesta no es reinventar SSTables/manifest/
compaction/bloom-filter en disco local (esa maquinaria existe *porque*
S3 no da mejor opción) — es usar un motor embebido que ya resuelve esto
de forma real: **`redb`** (puro safe Rust, `unsafe_code = forbid`
compatible, sin dependencia en C, ACID real, B-tree con MVCC, un solo
archivo, sin proceso ni puerto — sigue siendo "un binario").

## Estado actual de `LocalBackend` (verificado en código)

`crates/s3db/src/local.rs`: un archivo real por key
(`<key>`, `<key>.gqrev`, `<key>.gqlock`), CAS emulado con `flock`
exclusivo + comparación de contador + `write_atomic` (temp file + fsync
+ rename). Funciona, pero es exactamente lo que un motor de transacciones
embebido ya da de fábrica — reimplementado a mano, por key, sin
transacciones multi-key (`txn.rs` documenta explícitamente "no updates
in this version" porque el protocolo CAS-secuencial no puede dar rollback
limpio de un update ya aplicado; ese límite es del protocolo genérico,
no de lo que un filesystem local podría dar).

## Rediseño: un único archivo `redb` como motor de `LocalBackend`

- `{root}/s3db.redb` — una tabla `(key: &str) -> (version: u64, body: &[u8])`.
- `get`: read-transaction, directo.
- `put_cas`: write-transaction que lee `version` actual, compara contra
  `expected_etag`, escribe y comitea si coincide, aborta (sin tocar
  nada) si no — **real** atomicidad de redb, no `flock` + dos archivos
  sidecar.
- `list_prefix`: range scan nativo sobre keys con ese prefijo — B-tree
  real, no `walk_dir` recursivo por filesystem. Además queda ordenado
  por construcción, gratis.
- `get_range`/streaming: sin necesidad de un primitivo nuevo — acceso a
  redb ya es barato (mmap), no hace falta emular byte-range como en el
  documento LSM (ahí sí hace falta porque S3 cobra por request).

## Lo que modo local desbloquea (que remoto no puede, ni debe)

**1. Capability opcional, no cambia el trait base:**

```rust
#[async_trait::async_trait]
pub trait AtomicBackend: Backend {
    /// Todas las ops comitean en una sola write-transaction, o ninguna.
    /// Incluye updates, no solo creates -- a diferencia de txn::run hoy.
    async fn commit_batch(&self, ops: Vec<BatchOp>) -> Result<BatchOutcome>;
}
```

Solo `LocalBackend` lo implementa. `txn::run` detecta la capability
(downcast sobre el `Arc<dyn Backend>`, o un parámetro opcional al
construir el runner) y, si está presente, la usa en vez del protocolo
actual (`TxnRecord` + `recover_stale`). Ese protocolo **sigue intacto,
sin cambios, para S3/R2/Azure/GCS** — ahí sí hace falta, es la única
forma de dar algo parecido a atomicidad sin transacción nativa.

**2. Updates dentro de una transacción.** Ya no aplica la limitación
documentada en `txn.rs` — una write-transaction real de redb no necesita
que cada op sea "su propio lock" (la razón de que hoy sea create-only):
si cualquier op falla, ninguna se aplica, updates incluidos.

**3. Range scans e índices secundarios reales, sin encoding a mano.**
Las keys de redb soportan tipos ordenables nativos (enteros, tuplas) —
`SecondaryIndex::resolve_range` sobre `Local` es una llamada directa a
la API de rango de redb. No hace falta el `Segment::OrderedInt`/
`OrderedTimestamp` (encoding big-endian con bias) que el documento LSM sí
necesita para lograr lo mismo sobre S3.

**4. Fila + índice en la misma transacción atómica.** El diseño LSM
remoto no puede dar esto (cada manifest su propio CAS — 2PC cross-manifest
ya rechazado explícitamente). Local sí: una sola write-transaction de
redb cubre la fila y su entrada de índice a la vez, así que nunca hay
ventana donde el índice apunte a algo que la fila todavía no tiene (o al
revés).

## Qué NO cambia

- Backends S3-compatibles: exactamente el diseño de
  `docs/s3db-fulldb-roadmap.md`, sin filtración de nada de acá.
- Sin daemon nuevo: redb es librería embebida, un archivo en disco, cero
  proceso/puerto nuevo — mismo "un binario" de siempre.
- `flock` entre dos procesos de la misma máquina sigue siendo la única
  forma de exclusión entre procesos — lo que deja de hacer falta es
  implementarla a mano por key; redb ya serializa sus propias
  write-transactions internamente.

## Migración: formato en disco rompe, necesita herramienta explícita

El formato actual (archivo real + `.gqrev` + `.gqlock` por key) es
incompatible con un único `.redb` — no es cambio aditivo.

1. `LocalParams` gana `engine: "files" | "redb"` (default `"files"`
   hasta que la migración esté probada en producción propia).
2. Herramienta explícita `s3db-local-migrate`: `scroll` de todas las
   keys del formato viejo, escritas dentro de una sola write-transaction
   redb. **Nunca migración silenciosa al arrancar** — mismo principio que
   "nunca borrar datos reales sin avisar", aplicado acá a un cambio de
   formato local en vez de a un borrado.

## Cifrado: mismo diseño que el documento LSM, aplica igual acá

`LocalBackend` sobre `redb` sigue sellando cada `body` con
`s3db_crypto::Cipher` antes de escribirlo a la tabla — el motor de
storage cambia, el punto donde se cifra no. La sección de cifrado de
`docs/s3db-fulldb-roadmap.md` (`CipherAlgorithm`/`EncryptionMode`, header
byte bound-into-AAD, opt-out explícito, default on con
`XChaCha20Poly1305`) aplica sin cambios acá — no hay nada específico de
`redb` que la generalidad de algoritmo necesite tocar dos veces, es el
mismo `Cipher` compartido.

## Dependencia nueva

`redb` — única dependencia que este documento introduce. Puro safe Rust,
compatible con `unsafe_code = forbid`, sin C. No aplica al resto del
crate: los backends S3-compatibles siguen con motor propio (LSM hand-
rolled), sin este ni ningún otro dependency nuevo.

## Fases

| Fase | Qué construye | Depende de |
|---|---|---|
| 1 ✅ | `LocalBackend` sobre `redb` (get/put_cas/delete/list_prefix), detrás de `engine = "redb"` | — |
| 2 ✅ | `s3db-local-migrate` (files → redb) | 1 |
| 3 ✅ | `AtomicBackend` + `txn::run` lo detecta y usa cuando está presente (updates reales) | 1 |
| 4 | `SecondaryIndex::resolve_range` sobre Local vía rango nativo redb | 1 |
| 5 | Fila + índice en la misma transacción atómica | 3, 4 |

**Orden real:** 1 primero (nada más aplica sin esto). 2 y 3 en paralelo
una vez 1 esté. 4 depende solo de 1. 5 depende de 3 y 4 juntos.
