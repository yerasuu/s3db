use super::*;

fn stats(min: Value, max: Value) -> ColumnStats {
    ColumnStats {
        min: Some(min),
        max: Some(max),
    }
}

#[test]
fn eq_matches_only_the_exact_value() {
    let p = Predicate::Eq(0, Value::Int64(5));
    assert!(p.matches(&[Value::Int64(5)]));
    assert!(!p.matches(&[Value::Int64(6)]));
}

#[test]
fn lt_lte_gt_gte_match_as_expected() {
    assert!(Predicate::Lt(0, Value::Int64(5)).matches(&[Value::Int64(4)]));
    assert!(!Predicate::Lt(0, Value::Int64(5)).matches(&[Value::Int64(5)]));
    assert!(Predicate::Lte(0, Value::Int64(5)).matches(&[Value::Int64(5)]));
    assert!(Predicate::Gt(0, Value::Int64(5)).matches(&[Value::Int64(6)]));
    assert!(!Predicate::Gt(0, Value::Int64(5)).matches(&[Value::Int64(5)]));
    assert!(Predicate::Gte(0, Value::Int64(5)).matches(&[Value::Int64(5)]));
}

#[test]
fn matches_is_false_for_an_out_of_range_column() {
    let p = Predicate::Eq(3, Value::Int64(1));
    assert!(!p.matches(&[Value::Int64(1)]));
}

#[test]
fn matches_is_false_for_mismatched_kinds_on_a_non_eq_predicate() {
    let p = Predicate::Lt(0, Value::Int64(5));
    assert!(!p.matches(&[Value::Text("nope".into())]));
}

#[test]
fn eq_matches_uses_plain_equality_even_for_non_orderable_kinds() {
    let p = Predicate::Eq(0, Value::Bytes(vec![1, 2, 3]));
    assert!(p.matches(&[Value::Bytes(vec![1, 2, 3])]));
    assert!(!p.matches(&[Value::Bytes(vec![9])]));
}

#[test]
fn cannot_match_is_false_when_the_block_has_no_stats() {
    let p = Predicate::Gt(0, Value::Int64(5));
    assert!(!p.cannot_match(&ColumnStats::default()));
}

#[test]
fn gt_prunes_a_block_whose_max_is_not_greater_than_the_bound() {
    let p = Predicate::Gt(0, Value::Int64(10));
    assert!(p.cannot_match(&stats(Value::Int64(1), Value::Int64(10))));
    assert!(!p.cannot_match(&stats(Value::Int64(1), Value::Int64(11))));
}

#[test]
fn gte_prunes_a_block_whose_max_is_less_than_the_bound() {
    let p = Predicate::Gte(0, Value::Int64(10));
    assert!(p.cannot_match(&stats(Value::Int64(1), Value::Int64(9))));
    assert!(!p.cannot_match(&stats(Value::Int64(1), Value::Int64(10))));
}

#[test]
fn lt_prunes_a_block_whose_min_is_not_less_than_the_bound() {
    let p = Predicate::Lt(0, Value::Int64(10));
    assert!(p.cannot_match(&stats(Value::Int64(10), Value::Int64(20))));
    assert!(!p.cannot_match(&stats(Value::Int64(9), Value::Int64(20))));
}

#[test]
fn lte_prunes_a_block_whose_min_is_greater_than_the_bound() {
    let p = Predicate::Lte(0, Value::Int64(10));
    assert!(p.cannot_match(&stats(Value::Int64(11), Value::Int64(20))));
    assert!(!p.cannot_match(&stats(Value::Int64(10), Value::Int64(20))));
}

#[test]
fn eq_prunes_a_block_whose_range_does_not_contain_the_value() {
    let p = Predicate::Eq(0, Value::Int64(5));
    assert!(p.cannot_match(&stats(Value::Int64(10), Value::Int64(20))));
    assert!(p.cannot_match(&stats(Value::Int64(0), Value::Int64(4))));
    assert!(!p.cannot_match(&stats(Value::Int64(0), Value::Int64(10))));
}

/// A predicate compared against stats of a different kind is undecidable,
/// not a crash, and (safely) never prunes.
#[test]
fn cannot_match_is_false_for_mismatched_kinds() {
    let p = Predicate::Gt(0, Value::Int64(5));
    assert!(!p.cannot_match(&stats(Value::Text("a".into()), Value::Text("z".into()))));
}
