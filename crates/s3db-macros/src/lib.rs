//! `#[derive(Entity)]`: generates the `Collection`/`SecondaryIndex`
//! boilerplate every hand-written entity (`User`, `Group`, `RepoConfig`, ...)
//! in gitquarry already wrote by hand — one `key` field backing a
//! `Collection`, plus one `SecondaryIndex` and its pointer-struct/claim/
//! resolve/release trio per `#[entity(index)]` field. Never touches storage
//! itself: every generated method just calls straight into `s3db::{Collection,
//! SecondaryIndex, Segment}`, so the CAS/encryption contract is exactly the
//! one already documented there — this only removes the copy-pasted plumbing
//! around it.

use proc_macro::TokenStream;
use quote::{format_ident, quote};
use syn::{Data, DeriveInput, Fields, Lit, Meta, parse_macro_input};

/// Container attribute: `#[entity(collection = "...")]`, optional
/// `#[entity(suffix = "...")]` (defaults to `.json`, same as
/// `Collection::new`).
struct ContainerArgs {
    collection: String,
    suffix: Option<String>,
}

/// One `#[entity(index)]`/`#[entity(index(segment = "base64"))]` field —
/// `segment` defaults to `Segment::Raw`, same default shape as every
/// hand-written index in `auth::access` that isn't base64-encoding a
/// fingerprint/email.
struct IndexField {
    ident: syn::Ident,
    is_optional: bool,
    segment: Segment,
}

#[derive(Clone, Copy)]
enum Segment {
    Raw,
    Base64,
}

#[proc_macro_derive(Entity, attributes(entity))]
pub fn derive_entity(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

fn expand(input: DeriveInput) -> syn::Result<proc_macro2::TokenStream> {
    let struct_name = &input.ident;
    let container = parse_container_args(&input)?;

    let Data::Struct(data) = &input.data else {
        return Err(syn::Error::new_spanned(&input, "#[derive(Entity)] only supports structs"));
    };
    let Fields::Named(fields) = &data.fields else {
        return Err(syn::Error::new_spanned(&input, "#[derive(Entity)] requires named fields"));
    };

    let mut key_field: Option<syn::Ident> = None;
    let mut index_fields = Vec::new();
    for field in &fields.named {
        let ident = field.ident.clone().expect("named field");
        let mut has_key = false;
        let mut index_args: Option<Segment> = None;
        for attr in &field.attrs {
            if !attr.path().is_ident("entity") {
                continue;
            }
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("key") {
                    has_key = true;
                    return Ok(());
                }
                if meta.path.is_ident("index") {
                    if meta.input.peek(syn::token::Paren) {
                        let mut segment = Segment::Raw;
                        meta.parse_nested_meta(|inner| {
                            if inner.path.is_ident("segment") {
                                let value = inner.value()?;
                                let lit: Lit = value.parse()?;
                                if let Lit::Str(s) = lit {
                                    segment = match s.value().as_str() {
                                        "base64" => Segment::Base64,
                                        "raw" => Segment::Raw,
                                        other => {
                                            return Err(syn::Error::new_spanned(
                                                s,
                                                format!("unknown segment kind {other:?}, expected \"raw\" or \"base64\""),
                                            ));
                                        }
                                    };
                                }
                                Ok(())
                            } else {
                                Err(inner.error("unsupported #[entity(index(...))] key"))
                            }
                        })?;
                        index_args = Some(segment);
                    } else {
                        index_args = Some(Segment::Raw);
                    }
                    return Ok(());
                }
                Err(meta.error("unsupported #[entity(...)] attribute"))
            })?;
        }
        if has_key {
            if key_field.is_some() {
                return Err(syn::Error::new_spanned(&field.ident, "only one field may be #[entity(key)]"));
            }
            key_field = Some(ident.clone());
        }
        if let Some(segment) = index_args {
            let is_optional = is_option_type(&field.ty);
            index_fields.push(IndexField { ident, is_optional, segment });
        }
    }

    let key_field = key_field.ok_or_else(|| syn::Error::new_spanned(&input, "#[derive(Entity)] requires one field marked #[entity(key)]"))?;

    let collection_prefix = &container.collection;
    let suffix_tokens = match &container.suffix {
        Some(suffix) => quote! { s3db::Collection::new_with_suffix(#collection_prefix, #suffix) },
        None => quote! { s3db::Collection::new(#collection_prefix) },
    };

    let mut index_items = Vec::new();
    let mut index_methods = Vec::new();
    for index in &index_fields {
        let field_ident = &index.ident;
        let const_name = format_ident!("{}_INDEX", field_ident.to_string().to_uppercase());
        let pointer_name = format_ident!("__{struct_name}{}Pointer", to_camel(&field_ident.to_string()));
        let kind = field_ident.to_string();
        let segment_tokens = match index.segment {
            Segment::Raw => quote! { s3db::Segment::Raw },
            Segment::Base64 => quote! { s3db::Segment::Base64 },
        };
        let find_by = format_ident!("find_by_{field_ident}");
        let claim = format_ident!("claim_{field_ident}");
        let release = format_ident!("release_{field_ident}");

        index_items.push(quote! {
            #[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
            struct #pointer_name {
                key: String,
            }

            impl #struct_name {
                /// Generated from `#[entity(index)]` on `#field_ident` —
                /// same `{root}/{kind}/{segment}.json -> pointer` shape every
                /// hand-written secondary index in this codebase already uses.
                pub const #const_name: s3db::SecondaryIndex = s3db::SecondaryIndex::new(#collection_prefix, #kind, #segment_tokens);
            }
        });

        let value_expr = if index.is_optional {
            quote! { self.#field_ident.as_deref() }
        } else {
            quote! { Some(self.#field_ident.as_str()) }
        };

        index_methods.push(quote! {
            /// Single-attempt CAS claim of this entity's `#field_ident` in
            /// its index — see [`s3db::SecondaryIndex::claim_once`] for the
            /// exact conflict semantics. A no-op returning `true` if the
            /// field is `None` on an optional index.
            pub async fn #claim(&self, backend: &dyn s3db::Backend, cipher: &s3db::Cipher) -> anyhow::Result<bool> {
                match #value_expr {
                    Some(raw) => Self::#const_name.claim_once(backend, cipher, raw, &#pointer_name { key: self.#key_field.clone() }).await,
                    None => Ok(true),
                }
            }

            /// Resolves `raw` through the `#field_ident` index, then fetches
            /// the entity it points at — the two-hop pattern every hand-
            /// written index-backed lookup in this codebase already follows.
            pub async fn #find_by(backend: &dyn s3db::Backend, cipher: &s3db::Cipher, raw: &str) -> anyhow::Result<Option<Self>> {
                let (pointer, _etag) = Self::#const_name.resolve::<#pointer_name>(backend, cipher, raw).await?;
                let Some(pointer) = pointer else { return Ok(None) };
                Ok(Self::get(backend, cipher, &pointer.key).await?.0)
            }

            /// Best-effort release of this `#field_ident` claim — a no-op if
            /// the field is `None` on an optional index.
            pub async fn #release(&self, backend: &dyn s3db::Backend) {
                if let Some(raw) = #value_expr {
                    Self::#const_name.release(backend, raw).await;
                }
            }
        });
    }

    let expanded = quote! {
        impl #struct_name {
            /// Generated from `#[entity(collection = #collection_prefix)]`.
            pub const COLLECTION: s3db::Collection = #suffix_tokens;

            /// Reads by key. `None` if it doesn't exist yet — same
            /// convention as [`s3db::Collection::get`].
            pub async fn get(backend: &dyn s3db::Backend, cipher: &s3db::Cipher, key: &str) -> anyhow::Result<(Option<Self>, Option<String>)>
            where
                Self: serde::de::DeserializeOwned + Default,
            {
                Self::COLLECTION.get(backend, cipher, key).await
            }

            /// Compare-and-swap write, keyed by this entity's own
            /// `#key_field` field. `expected_etag = None` means "must not
            /// exist yet" — same convention as [`s3db::Collection::put`].
            pub async fn put(&self, backend: &dyn s3db::Backend, cipher: &s3db::Cipher, expected_etag: Option<&str>) -> anyhow::Result<s3db::Cas>
            where
                Self: serde::Serialize,
            {
                Self::COLLECTION.put(backend, cipher, &self.#key_field, self, expected_etag).await
            }

            /// Best-effort delete by key.
            pub async fn delete(backend: &dyn s3db::Backend, key: &str) {
                Self::COLLECTION.delete(backend, key).await
            }

            /// Every key currently stored, sorted.
            pub async fn list_keys(backend: &dyn s3db::Backend) -> anyhow::Result<Vec<String>> {
                Self::COLLECTION.list_names(backend).await
            }

            #(#index_methods)*
        }

        #(#index_items)*
    };

    Ok(expanded)
}

fn is_option_type(ty: &syn::Type) -> bool {
    if let syn::Type::Path(type_path) = ty {
        return type_path.path.segments.last().is_some_and(|seg| seg.ident == "Option");
    }
    false
}

fn to_camel(field_name: &str) -> String {
    field_name.split('_').map(|part| {
        let mut chars = part.chars();
        match chars.next() {
            Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
            None => String::new(),
        }
    }).collect()
}

fn parse_container_args(input: &DeriveInput) -> syn::Result<ContainerArgs> {
    let mut collection = None;
    let mut suffix = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("entity") {
            continue;
        }
        if !matches!(&attr.meta, Meta::List(_)) {
            return Err(syn::Error::new_spanned(attr, "expected #[entity(collection = \"...\")]"));
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("collection") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                collection = Some(lit.value());
                return Ok(());
            }
            if meta.path.is_ident("suffix") {
                let value = meta.value()?;
                let lit: syn::LitStr = value.parse()?;
                suffix = Some(lit.value());
                return Ok(());
            }
            Err(meta.error("unsupported #[entity(...)] key, expected \"collection\" or \"suffix\""))
        })?;
    }
    let collection = collection.ok_or_else(|| syn::Error::new_spanned(input, "#[derive(Entity)] requires #[entity(collection = \"...\")]"))?;
    Ok(ContainerArgs { collection, suffix })
}
