use super::*;
use crate::lsm::value::ColumnDef;

fn schema() -> Schema {
    Schema::new(vec![
        ColumnDef {
            name: "age".to_string(),
            kind: ValueKind::Int64,
        },
        ColumnDef {
            name: "name".to_string(),
            kind: ValueKind::Text,
        },
    ])
}

fn put(age: i64, name: &str) -> MemValue {
    MemValue::Put(rmp_serde::to_vec_named(&vec![Value::Int64(age), Value::Text(name.to_string())]).unwrap())
}

#[test]
fn encode_then_decode_round_trips_every_row() {
    let schema = schema();
    let rows = vec![(b"a".to_vec(), put(30, "alice")), (b"b".to_vec(), put(25, "bob"))];
    let (bytes, _) = encode(&schema, &rows).unwrap();
    let decoded = decode(&schema, &bytes).unwrap();
    assert_eq!(decoded, rows);
}

#[test]
fn tombstones_survive_the_round_trip() {
    let schema = schema();
    let rows = vec![(b"a".to_vec(), put(30, "alice")), (b"b".to_vec(), MemValue::Tombstone)];
    let (bytes, _) = encode(&schema, &rows).unwrap();
    assert_eq!(decode(&schema, &bytes).unwrap(), rows);
}

#[test]
fn encode_rejects_a_row_with_the_wrong_column_count() {
    let schema = schema();
    let bad = MemValue::Put(rmp_serde::to_vec_named(&vec![Value::Int64(1)]).unwrap());
    assert!(encode(&schema, &[(b"a".to_vec(), bad)]).is_err());
}

#[test]
fn encode_rejects_a_row_with_a_column_type_mismatch() {
    let schema = schema();
    let bad = MemValue::Put(rmp_serde::to_vec_named(&vec![Value::Text("x".into()), Value::Text("y".into())]).unwrap());
    assert!(encode(&schema, &[(b"a".to_vec(), bad)]).is_err());
}

#[test]
fn column_stats_computes_min_and_max_over_live_rows() {
    let schema = schema();
    let rows = vec![
        (b"a".to_vec(), put(30, "charlie")),
        (b"b".to_vec(), put(10, "alice")),
        (b"c".to_vec(), put(20, "bob")),
    ];
    let (_, stats) = encode(&schema, &rows).unwrap();
    assert_eq!(
        stats[0],
        ColumnStats {
            min: Some(Value::Int64(10)),
            max: Some(Value::Int64(30)),
        }
    );
    assert_eq!(
        stats[1],
        ColumnStats {
            min: Some(Value::Text("alice".into())),
            max: Some(Value::Text("charlie".into())),
        }
    );
}

#[test]
fn column_stats_ignores_tombstoned_rows() {
    let schema = schema();
    let rows = vec![(b"a".to_vec(), put(30, "alice")), (b"b".to_vec(), MemValue::Tombstone)];
    let (_, stats) = encode(&schema, &rows).unwrap();
    assert_eq!(stats[0].min, Some(Value::Int64(30)));
    assert_eq!(stats[0].max, Some(Value::Int64(30)));
}

#[test]
fn column_stats_is_none_when_every_row_is_a_tombstone() {
    let schema = schema();
    let rows = vec![(b"a".to_vec(), MemValue::Tombstone)];
    let (_, stats) = encode(&schema, &rows).unwrap();
    assert_eq!(stats[0], ColumnStats::default());
}

#[test]
fn column_stats_is_none_for_non_orderable_kinds() {
    let schema = Schema::new(vec![ColumnDef {
        name: "blob".to_string(),
        kind: ValueKind::Bytes,
    }]);
    let row = MemValue::Put(rmp_serde::to_vec_named(&vec![Value::Bytes(vec![1, 2, 3])]).unwrap());
    let (_, stats) = encode(&schema, &[(b"a".to_vec(), row)]).unwrap();
    assert_eq!(stats[0], ColumnStats::default());
}

#[test]
fn decode_rejects_a_column_count_mismatch() {
    let schema = schema();
    let rows = vec![(b"a".to_vec(), put(1, "a"))];
    let (bytes, _) = encode(&schema, &rows).unwrap();
    let wrong_schema = Schema::new(vec![ColumnDef {
        name: "only_one".to_string(),
        kind: ValueKind::Int64,
    }]);
    assert!(decode(&wrong_schema, &bytes).is_err());
}

#[test]
fn all_orderable_kinds_compute_stats_correctly() {
    let schema = Schema::new(vec![
        ColumnDef {
            name: "f".to_string(),
            kind: ValueKind::Float64,
        },
        ColumnDef {
            name: "t".to_string(),
            kind: ValueKind::Timestamp,
        },
        ColumnDef {
            name: "b".to_string(),
            kind: ValueKind::Bool,
        },
    ]);
    let row = |f: f64, t: i64, b: bool| {
        MemValue::Put(rmp_serde::to_vec_named(&vec![Value::Float64(f), Value::Timestamp(t), Value::Bool(b)]).unwrap())
    };
    let rows = vec![
        (b"a".to_vec(), row(2.5, 200, false)),
        (b"b".to_vec(), row(1.0, 100, true)),
    ];
    let (_, stats) = encode(&schema, &rows).unwrap();
    assert_eq!(stats[0].min, Some(Value::Float64(1.0)));
    assert_eq!(stats[0].max, Some(Value::Float64(2.5)));
    assert_eq!(stats[1].min, Some(Value::Timestamp(100)));
    assert_eq!(stats[1].max, Some(Value::Timestamp(200)));
    assert_eq!(stats[2].min, Some(Value::Bool(false)));
    assert_eq!(stats[2].max, Some(Value::Bool(true)));
}
