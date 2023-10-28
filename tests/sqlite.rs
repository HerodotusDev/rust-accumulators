use mmr::store::{counter::InStoreCounter, sqlite::SQLiteStore, IStore};
use std::{collections::HashMap, rc::Rc};

#[test]
fn set_and_get_value() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();
    store.set("key", "value").unwrap();
    let value = store.get("key").unwrap();
    assert_eq!(value.unwrap(), "value");
}

#[test]
fn set_and_get_many_values() {
    let mut store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();
    let mut entries = HashMap::new();
    entries.insert("key1".to_string(), "value1".to_string());
    entries.insert("key2".to_string(), "value2".to_string());

    store.set_many(entries).unwrap();

    let values = store.get_many(vec!["key1", "key2"]).unwrap();

    assert_eq!(values.get("key1"), Some(&"value1".to_string()));
}

#[test]
fn get_many_values_in_correct_order() {
    let mut store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();
    let mut entries = HashMap::new();
    entries.insert("a".to_string(), "value1".to_string());
    entries.insert("b".to_string(), "value2".to_string());
    entries.insert("10".to_string(), "value3".to_string());
    entries.insert("5".to_string(), "value4".to_string());

    store.set_many(entries).unwrap();

    let keys = vec!["a", "b", "10", "5"];

    let values = store.get_many(keys).unwrap();

    assert_eq!(values.get("a"), Some(&"value1".to_string()));
    assert_eq!(values.get("b"), Some(&"value2".to_string()));
    assert_eq!(values.get("10"), Some(&"value3".to_string()));
    assert_eq!(values.get("5"), Some(&"value4".to_string()));
}

#[test]
fn should_delete_a_value() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();

    store.set("key", "value").unwrap();
    store.delete("key").unwrap();
    let value = store.get("key").unwrap();

    assert_eq!(value, None);
}

#[test]
fn test_in_store_counter() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();

    // Create an in-store counter
    let counter = InStoreCounter::new(Rc::new(store), "counter".to_string());
    counter.set(10);
    let value = counter.get().unwrap();
    assert_eq!(value, 10);
    let newcounter = counter.increment().unwrap();
    assert_eq!(newcounter, 11);
}
