//! Opt-in, read-only JSON REST server for browsing collections by hand —
//! the same read path `s3db-inspect` walks from a terminal, over HTTP
//! instead of argv, for whoever wants a "just show me the data" view
//! without a CLI. Behind the `rest` cargo feature (off by default): a
//! storage library has no business linking axum unless a caller actually
//! asks for it.
//!
//! **No authentication.** [`serve`] decrypts and serves plaintext JSON on
//! whatever socket it's told to bind, with nothing else in front of it —
//! binding `127.0.0.1` is what keeps that off the network; a caller that
//! binds anywhere else is choosing, deliberately, to expose decrypted data.
//!
//! Collections are discovered, not registered: [`discover_collections`]
//! walks every key once and takes the top-level path segment as a
//! collection name, skipping anything starting with `.` (this crate's own
//! bookkeeping — `.conf`, and every collection's own `.history`/`.deleted`/
//! `.created`, which live one level deeper and never surface here anyway).
//! A collection name arriving from a URL is still run through the same
//! [`crate::naming::validate_path`] every entity name gets, since nothing
//! about coming from discovery instead of the network makes that check
//! unnecessary to repeat at this edge.

use crate::backend::Backend;
use crate::cipher::Cipher;
use crate::collection::Collection;
use crate::naming::validate_path;
use anyhow::{Context, Result};
use axum::Router;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;

/// Page size for both collection discovery and entry listing. Not
/// caller-configurable: this is an admin/debug endpoint, not a tuned hot
/// path, and one constant is one fewer knob to document.
const PAGE: usize = 500;

#[derive(Clone)]
struct AppState {
    backend: Arc<dyn Backend>,
    cipher: Cipher,
}

#[derive(Serialize)]
struct CollectionsBody {
    collections: Vec<String>,
}

#[derive(Serialize)]
struct EntriesBody {
    entries: Vec<String>,
    next_after: Option<String>,
}

#[derive(Deserialize)]
struct PageQuery {
    after: Option<String>,
    limit: Option<usize>,
}

enum ApiError {
    BadRequest(String),
    NotFound(String),
    Internal(anyhow::Error),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            ApiError::NotFound(message) => (StatusCode::NOT_FOUND, message),
            ApiError::Internal(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
        };
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

/// Serves the REST API on `addr` until the listener fails or the returned
/// future is dropped — same "runs forever, caller decides how to host it"
/// shape as any other long-running server; wrap it in `tokio::spawn` for a
/// background admin port, or `.await` it directly if it's the whole
/// process.
/// Builds the router without binding anything — split out from [`serve`] so
/// tests can drive it directly with `tower::ServiceExt::oneshot` instead of
/// racing a real socket.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/collections", get(list_collections))
        .route("/collections/{name}", get(list_entries))
        .route("/collections/{name}/{item}", get(get_entry))
        .with_state(state)
}

pub async fn serve(backend: Arc<dyn Backend>, cipher: Cipher, addr: SocketAddr) -> Result<()> {
    let app = router(AppState { backend, cipher });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("binding s3db REST listener to {addr}"))?;
    axum::serve(listener, app).await.context("s3db REST server")
}

/// The bucket's top-level path segments, minus anything starting with `.`.
/// Walks every key in the bucket once per call — acceptable for an
/// admin/debug endpoint, wrong for anything called often, which this isn't.
async fn discover_collections(backend: &dyn Backend) -> Result<Vec<String>> {
    let mut names = BTreeSet::new();
    let mut after: Option<String> = None;
    loop {
        let page = backend.list_page("", after.as_deref(), PAGE).await?;
        for (key, _size) in &page.entries {
            if let Some(top) = key.split('/').next()
                && !top.is_empty()
                && !top.starts_with('.')
            {
                names.insert(top.to_string());
            }
        }
        match page.next_after {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    Ok(names.into_iter().collect())
}

async fn list_collections(State(state): State<AppState>) -> Result<Json<CollectionsBody>, ApiError> {
    let collections = discover_collections(state.backend.as_ref())
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(CollectionsBody { collections }))
}

async fn list_entries(
    State(state): State<AppState>,
    UrlPath(name): UrlPath<String>,
    Query(page): Query<PageQuery>,
) -> Result<Json<EntriesBody>, ApiError> {
    validate_path(&name, "collection name").map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let limit = page.limit.unwrap_or(PAGE).min(PAGE);
    let collection = Collection::new_owned(name);
    let (entries, next_after) = collection
        .list_names_page(state.backend.as_ref(), page.after.as_deref(), limit)
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(EntriesBody { entries, next_after }))
}

async fn get_entry(
    State(state): State<AppState>,
    UrlPath((name, item)): UrlPath<(String, String)>,
) -> Result<Json<serde_json::Value>, ApiError> {
    validate_path(&name, "collection name").map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let collection = Collection::new_owned(name);
    let key = collection.key(&item).map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let (sealed, etag) = state.backend.get(&key).await.map_err(ApiError::Internal)?;
    if etag.is_none() {
        return Err(ApiError::NotFound(format!("{item:?} not found")));
    }
    let plain = state
        .cipher
        .open(&key, &sealed)
        .with_context(|| format!("decrypting {key}"))
        .map_err(ApiError::Internal)?;
    // `rmpv::Value`, no `serde_json::Value`, directo: MessagePack tiene un
    // tipo binario que JSON no tiene, y bastante entidad de uso real trae uno
    // sin que el caller lo haya pedido -- `Uuid`, por ejemplo, serializa como
    // string en JSON pero como bytes crudos en cualquier formato
    // no-human-readable (ver `Serializer::is_human_readable`), MessagePack
    // entre ellos. Decodificar directo a `serde_json::Value` hacía fallar la
    // lectura de CUALQUIER entidad con un campo así con "not
    // JSON-representable" — precisión correcta, pero inútil para el caso de
    // uso real de este endpoint (mirar los datos), así que se convierte
    // (`rmpv_to_json`) en vez de exigir que todo el valor ya sea JSON puro.
    let raw: rmpv::Value = rmp_serde::from_slice(&plain)
        .with_context(|| format!("{key} is not a valid MessagePack value"))
        .map_err(ApiError::Internal)?;
    Ok(Json(rmpv_to_json(raw)))
}

/// Convierte cualquier `rmpv::Value` a `serde_json::Value`. Los dos tipos que
/// JSON no tiene se codifican como string en vez de hacer fallar la
/// conversión entera:
/// - `Binary` → `"base64:<...>"` (el caso real: un `Uuid` u otro campo que
///   serializa como bytes crudos en MessagePack).
/// - `Ext` (tipo, bytes) → `"ext:<tipo>:base64:<...>"` — este crate no
///   escribe extensiones msgpack hoy, pero un lector genérico no debería
///   asumirlo para siempre.
/// Un entero fuera del rango de `i64`/`u64` (posible en teoría, msgpack
/// soporta hasta u64 completo y esto ya lo cubre) cae a su representación en
/// texto antes que perder precisión silenciosamente redondeando a `f64`.
fn rmpv_to_json(value: rmpv::Value) -> serde_json::Value {
    use rmpv::Value as V;
    use serde_json::Value as J;

    match value {
        V::Nil => J::Null,
        V::Boolean(b) => J::Bool(b),
        V::Integer(i) => i
            .as_i64()
            .map(J::from)
            .or_else(|| i.as_u64().map(J::from))
            .unwrap_or_else(|| J::String(i.to_string())),
        V::F32(f) => serde_json::Number::from_f64(f as f64).map(J::Number).unwrap_or(J::Null),
        V::F64(f) => serde_json::Number::from_f64(f).map(J::Number).unwrap_or(J::Null),
        // Bytes que se declararon "string" en el msgpack pero no son UTF-8
        // válido: no hay representación de texto razonable, así que se
        // tratan como binario (mismo prefijo que `Binary`). `is_str()` (que
        // solo pide un `&self`) decide la rama ANTES de mover `s` con
        // `into_str`/`into_bytes` -- pedir las dos por valor a la vez no
        // compila (`Utf8String` no es `Copy`).
        V::String(s) if s.is_str() => J::String(s.into_str().expect("is_str() ya lo confirmó")),
        V::String(s) => J::String(format!("base64:{}", BASE64.encode(s.into_bytes()))),
        V::Binary(bytes) => J::String(format!("base64:{}", BASE64.encode(bytes))),
        V::Array(items) => J::Array(items.into_iter().map(rmpv_to_json).collect()),
        V::Map(entries) => {
            let mut map = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries {
                let key = match k {
                    V::String(s) => s.into_str().unwrap_or_else(|| "<non-utf8 key>".to_string()),
                    other => rmpv_to_json(other).to_string(),
                };
                map.insert(key, rmpv_to_json(v));
            }
            J::Object(map)
        }
        V::Ext(tag, bytes) => J::String(format!("ext:{tag}:base64:{}", BASE64.encode(bytes))),
    }
}

#[cfg(test)]
#[path = "../tests/unit/rest.rs"]
mod tests;
