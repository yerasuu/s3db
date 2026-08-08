use super::*;

fn schema() -> Schema {
    Schema::new(vec![
        ColumnDef {
            name: "id".to_string(),
            kind: ValueKind::Int64,
        },
        ColumnDef {
            name: "name".to_string(),
            kind: ValueKind::Text,
        },
    ])
}

#[test]
fn validate_accepts_a_matching_row() {
    assert!(schema().validate(&[Value::Int64(1), Value::Text("a".into())]).is_ok());
}

#[test]
fn validate_rejects_the_wrong_number_of_values() {
    let err = schema().validate(&[Value::Int64(1)]).unwrap_err();
    assert!(err.to_string().contains("1 value"), "got: {err}");
}

#[test]
fn validate_rejects_a_column_type_mismatch() {
    let err = schema()
        .validate(&[Value::Text("a".into()), Value::Text("b".into())])
        .unwrap_err();
    assert!(err.to_string().contains("Int64"), "got: {err}");
}

#[test]
fn kind_matches_the_variant() {
    assert_eq!(Value::Int64(1).kind(), ValueKind::Int64);
    assert_eq!(Value::Float64(1.0).kind(), ValueKind::Float64);
    assert_eq!(Value::Text("x".into()).kind(), ValueKind::Text);
    assert_eq!(Value::Bytes(vec![1]).kind(), ValueKind::Bytes);
    assert_eq!(Value::Timestamp(1).kind(), ValueKind::Timestamp);
    assert_eq!(Value::Bool(true).kind(), ValueKind::Bool);
    assert_eq!(Value::Array(vec![]).kind(), ValueKind::Array);
    assert_eq!(Value::Json(serde_json::Value::Null).kind(), ValueKind::Json);
}

#[test]
fn only_the_documented_kinds_are_orderable() {
    for kind in [
        ValueKind::Int64,
        ValueKind::Float64,
        ValueKind::Text,
        ValueKind::Timestamp,
        ValueKind::Bool,
    ] {
        assert!(Value::is_orderable(kind), "{kind:?} should be orderable");
    }
    for kind in [ValueKind::Bytes, ValueKind::Array, ValueKind::Json] {
        assert!(!Value::is_orderable(kind), "{kind:?} should not be orderable");
    }
}

#[test]
fn value_round_trips_through_messagepack() {
    for value in [
        Value::Int64(-5),
        Value::Float64(1.5),
        Value::Text("hello".into()),
        Value::Bytes(vec![1, 2, 3]),
        Value::Timestamp(1_700_000_000_000),
        Value::Bool(true),
        Value::Array(vec![Value::Int64(1), Value::Text("nested".into())]),
        Value::Json(serde_json::json!({"a": 1})),
    ] {
        let bytes = rmp_serde::to_vec_named(&value).unwrap();
        let back: Value = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(back, value);
    }
}
