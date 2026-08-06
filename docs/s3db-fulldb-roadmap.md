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
> (mismo principio que el resto de gitquarry). Nada acá agrega un proceso
> nuevo, un puerto nuevo, ni un protocolo de consenso.

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

**5. Compactor en background** — merge estándar LSM (leveled o tiered)
de SSTables viejos en uno nuevo, purga tombstones expirados. Reemplaza
`gc.rs`/`maintenance.rs` con una sola responsabilidad clara: mantener el
número de SSTables acotado y la amplificación de lectura baja.

**6. Lectura.**
- *Point lookup*: bloom filter por SSTable descarta las que no contienen
  la key sin abrirlas; binary search en `block_index`; **un `GET` con
  `Range` header** trae solo el bloque relevante, no el objeto entero.
- *Range scan*: merge-iterator sobre los SSTables cuyo rango se solapa
  con la query — ya están ordenados por construcción, es un scan
  contiguo real, no N gets.

**Cambio de trait necesario.** `Backend` hoy declara explícitamente "no
byte-range" (`backend.rs`, doc del trait). Este diseño necesita
`get_range(key, offset, len) -> Result<Vec<u8>>` — los 5 drivers ya
hablan HTTP y soportan `Range` nativo (S3/R2/GCS/Azure vía header
estándar, `Local` vía `seek`), así que es una implementación mecánica por
driver, no una capacidad nueva que haya que inventar.

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
| 1 | WAL + memtable + flush a SSTable (sin compactar) | Bootstrap del motor, nada existente |
| 2 | Manifest CAS + lectura (bloom + block index + `get_range`) | — |
| 3 | Compactor (merge + purga de tombstones) | `gc.rs`/`maintenance.rs`, para tablas LSM |
| 4 | Formato de bloque columnar tipado + schema declarado | — |
| 5 | Range scan + índice secundario (segundo LSM ordenado por otra key) | — |
| 6 | `TableLocation`/`BackendRegistry` (routing multi-backend) | — |
| 7 (opcional) | Query builder mínimo sobre 1-5 | — |

**Orden real:** 1 → 2 son bloque mínimo funcional (sin esto no hay motor).
3 puede esperar (SSTables sin compactar funcionan, solo degradan lectura
con el tiempo). 4 y 5 son el valor central del pedido original (tipo +
rango) y dependen de 1-2. 6 es independiente, se puede hacer en paralelo
a 3-5. 7 al final, condicionado a uso real.
