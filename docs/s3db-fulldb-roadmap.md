# Roadmap: `s3db` hacia motor de tipo libre / multi-sitio (estilo Postgres)

> **Diseño, todavía no implementado.** Este documento describe el plan tal
> como quedó acordado, no código existente. Ver `git log` para confirmar si
> alguna fase ya aterrizó antes de asumir que sigue pendiente.
>
> Presupone lectura de `docs/s3db.md` (documento base + extensión de
> escala). No repite lo que ya funciona ahí.

## Contexto

Hoy `s3db` es un almacén tipado de documentos JSON sobre object storage:
una `Collection<T>` guarda instancias de **un struct Rust fijo, conocido en
compile-time** (`#[derive(Entity)]`), bajo un único prefijo de key, en un
**único backend/bucket** por proceso. `SecondaryIndex`/`ShardedIndex`
resuelven lookups exactos (`Segment::Raw`/`Base64`), no rangos ni queries
compuestas. No hay lenguaje de queries, ni joins, ni motor de agregación.

El pedido es evolucionar esto en dos ejes, sin quedar "cerrado a datos en
un único sitio o de un único tipo":

- **Eje A — tipo libre**: una colección no debería exigir un struct Rust
  fijo por tipo de entidad, y debería soportar el rango de tipos de dato
  que Postgres da (enteros, floats, timestamps, arrays, texto, bytes) con
  índices que respeten cada tipo (rango, no solo igualdad).
- **Eje B — multi-sitio**: los datos no deberían estar atados a un único
  backend/bucket — distintas colecciones (o particiones de una colección)
  en distintos sitios/proveedores.

## Estado actual (verificado en código)

- `Collection<T>`/`Singleton<T>` (`collection.rs`): key =
  `{prefix}/{name}{suffix}` (o `{prefix}/{bucket:04x}/{name}{suffix}` con
  `KeyEntropy::HashPrefix`). `T` es un tipo Rust concreto, resuelto en
  compile-time vía `#[derive(Entity)]` (`s3db_macros`).
- `SecondaryIndex`/`ShardedIndex` (`index.rs`, `sharded_index.rs`): puntero
  `{root}/{kind}/{segment(raw)}.json → T`. `Segment::Raw`/`Base64` son las
  únicas dos formas de encodear la key — ambas exact-match, ninguna
  preserva orden numérico/temporal para rango.
- `BackendConfig` (`config.rs`) es un enum de 5 variantes (`S3`/`R2`/
  `Azure`/`Gcs`/`Local`); `build_backend` siempre construye **uno solo**
  (`Arc<dyn Backend>`). No existe hoy el concepto de "varios backends
  activos con routing por colección" — toda la app comparte un único
  `Backend` decorado (cache/resilience/métricas).
- No existe `_v`/schema-version en el código real — eso solo está
  *diseñado* en `docs/s3db.md` (extensión de escala, `MaintenanceScanner`),
  no implementado.
- No hay query language ni joins: todo acceso es `Collection::get(name)`
  exacto, `SecondaryIndex::resolve(raw)` exacto, o `scroll`/`list_all_keys`
  (listar un prefijo entero, sin filtro server-side más allá del prefijo
  mismo).

## Decisiones de diseño (fijadas para todo el roadmap)

- **No se persigue SQL real ni un optimizador de queries.** S3 no ejecuta
  nada server-side; cualquier "join" es fan-out de `get`s del lado
  cliente. Se declara así explícitamente en vez de prometer una paridad
  con Postgres que el sustrato no puede dar.
- **No se persigue replicación multi-writer entre sitios.** Eso requiere
  consenso, que S3 no ofrece — mismo motivo por el que `docs/s3db.md`
  rechaza explícitamente MVCC real. "Multi-sitio" acá significa *routing*
  de colecciones a distintos backends/buckets (particionado), no un
  clúster distribuido con quórum ni failover automático.
- **Cada fase es aditiva y opt-in.** Colecciones existentes (`Entity`
  derive, struct fijo, un solo backend) siguen funcionando sin cambios —
  mismo espíritu que `KeyEntropy::HashPrefix` o `IndexMode::Inline` en el
  doc de escala.

## Fase 1 — Documento de tipo libre

**Objetivo.** Una colección puede guardar entidades sin struct Rust fijado
en compile-time — primer paso del eje A, antes de tocar rango o
multi-sitio.

**Diseño.**

```rust
pub enum FieldValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Bytes(Vec<u8>),
    Timestamp(DateTime<Utc>),
    Array(Vec<FieldValue>),
    Object(BTreeMap<String, FieldValue>),
}

pub type Document = BTreeMap<String, FieldValue>;
```

Superset tipado de `serde_json::Value`, con variantes elegidas porque
admiten encoding lexicográfico ordenable (necesario en fase 2).
`Collection<Document>` convive con `Collection<T: Entity>` ya
existente — mismo esquema de key, `Document` es solo un `T` más para el
genérico que `Collection` ya tiene.

**Qué cambia.** Módulo nuevo `document.rs`. Nada en `collection.rs`/
`index.rs` se toca.

**Qué NO se hace todavía.** Sin validación de schema — eso queda como
fase 1b opcional: un `SchemaRegistry` declarativo por colección
(campos + tipo + requerido, versión explícita, chequeado en cada `put`),
mismo patrón que `EncryptionConfig`/`ShardEpoch` (config explícita, nunca
inferencia).

## Fase 2 — Índices por rango y compuestos

**Objetivo.** `SecondaryIndex` hoy solo hace exact-match. Queries tipo
"edad > 30" o "eventos entre fecha A y B" necesitan que la key del índice
preserve orden.

**Diseño.** `Segment` gana variantes con encoding ordenable (mismo truco
que RocksDB/FoundationDB: big-endian con bias de signo, para que
comparación lexicográfica == comparación numérica):

```rust
pub enum Segment {
    Raw,
    Base64,
    OrderedInt,       // i64 -> 8 bytes big-endian, bit de signo invertido
    OrderedFloat,      // f64 -> IEEE-754 bit tricks, mismo principio
    OrderedTimestamp,  // DateTime<Utc> -> OrderedInt de millis desde epoch
}
```

`SecondaryIndex` gana `resolve_range(low, high) -> impl Stream<Item = T>`,
que hace `list_prefix` acotado al rango de keys ya ordenadas — se apoya en
que S3 `list_prefix` devuelve orden lexicográfico, sin agregar nada nuevo
al `Backend` trait.

**Índices compuestos.** Concatenar `Segment`s encoded en orden fijo (mismo
patrón que un índice b-tree compuesto `(a, b)` en Postgres):
`kind = "age_name"`, `segment = encode(age) || "\0" || encode(name)`.

**Qué NO se hace.** Sin índices parciales (`WHERE` en el índice mismo),
sin GiST/GIN — no hay motor de expresiones que lo necesite todavía.

## Fase 3 — Fan-out joins (declarativos, no reales)

**Objetivo.** Resolver relaciones (FK) sin que cada caller reescriba a
mano el mismo patrón `get` → `get_many`.

**Diseño.**

```rust
pub struct Relation<T, U> {
    fk: fn(&T) -> &str,
    target: Collection, // o SecondaryIndex de U
}

impl<T, U: Entity> Relation<T, U> {
    async fn join(&self, rows: Vec<T>, loader: &BatchLoader) -> Vec<(T, Option<U>)>;
}
```

`join` usa `BatchLoader::load_many` (ya existe) por debajo — batching
real, no N+1, pero sigue siendo fan-out del lado cliente, nunca ejecución
server-side.

**Qué NO se hace.** Sin joins multi-hop optimizados automáticamente, sin
agregaciones (`COUNT`/`SUM`/`GROUP BY`) — requerirían escanear datasets
completos, ya identificado como caro en `docs/s3db.md`
(`MaintenanceScanner`). Si aparece necesidad real de agregación, la
respuesta es un contador mantenido incrementalmente en cada write, no un
motor de agregación genérico.

## Fase 4 — Routing multi-backend (colección → bucket/sitio)

**Objetivo.** Eje B: una colección puede vivir en un backend distinto al
resto, sin que la app arme un único `Arc<dyn Backend>` global.

**Diseño.**

```rust
pub struct BackendRegistry {
    backends: HashMap<String, Arc<dyn Backend>>, // "primary" siempre presente
}
```

`Collection`/`SecondaryIndex` ganan un campo opcional
`backend_id: &'static str` (default `"primary"` = comportamiento actual
sin cambios). En config, `BackendConfig` pasa de un único valor a un mapa
`nombre -> BackendConfig` en `gitquarry.toml`, con validación de que
`"primary"` siempre exista.

**Qué NO se hace.** Sin replicación activa entre backends (escribir 2x y
reconciliar conflictos es un mecanismo de consenso, rechazado por el mismo
motivo que el rechazo de MVCC real en `docs/s3db.md`). Un backend por
colección es *particionado*, no *replicación*: si un sitio cae, esa
colección específica cae con él, sin failover automático. Failover real
queda fuera de este roadmap.

## Fase 5 (opcional — evaluar después de 1-4) — Query builder mínimo

Azúcar sintáctica sobre las fases 1-3, no un motor nuevo:

```rust
query::<Document>("events")
    .filter("age", Cmp::Gt(30))
    .limit(50)
```

Arma internamente el `resolve_range` correcto de fase 2. Se implementa
solo si, tras las fases 1-4, hay uso real que lo justifique — no se
compromete de antemano (consistente con "no speculative abstractions" del
proyecto).

## Tabla resumen

| Fase | Eje | Módulo nuevo | Rompe algo existente |
|---|---|---|---|
| 1 | Tipo libre | `document.rs` | No, aditivo |
| 2 | Rango / compuestos | `index.rs`: `Segment::Ordered*` | No, aditivo |
| 3 | Joins fan-out | `relation.rs` | No, aditivo |
| 4 | Multi-backend | `backend_registry.rs`, `config.rs` | Config: `BackendConfig` pasa a mapa (breaking en config, no en API) |
| 5 | Query builder | `query.rs` (opcional) | No, aditivo |

## Orden recomendado

Fase 1 antes de fase 2 (rango necesita `FieldValue` ordenable). Fase 4 es
independiente — se puede hacer en paralelo a 1-3. Fase 3 depende de fase
1. Fase 5 al final, opcional, condicionada a uso real.
