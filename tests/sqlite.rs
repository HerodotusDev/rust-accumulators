use mmr::store::{counter::InStoreCounter, sqlite::SQLiteStore, table::InStoreTable, IStore};
use std::{collections::HashMap, rc::Rc};

#[test]
fn set_and_get_value() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();
    store
        .set(
            "6b9b77f2-a893-48bf-a52a-d5be5d0aaba3:RootHash",
            "0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804",
        )
        .unwrap();
    store.set("key", "value").unwrap();
    let value = store.get("key").unwrap();
    assert_eq!(value.unwrap(), "value");
    let value1 = store.get("6b9b77f2-a893-48bf-a52a-d5be5d0aaba3:RootHash");
    assert_eq!(
        value1.unwrap(),
        Some("0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804".to_string())
    );
}

#[test]
fn set_and_get_many_values() {
    let store = SQLiteStore::new(":memory:").unwrap();
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
    let store = SQLiteStore::new(":memory:").unwrap();
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
    let _ = counter.set(10);
    let value = counter.get();
    assert_eq!(value, 10);
    let newcounter = counter.increment().unwrap();
    assert_eq!(newcounter, 11);
}

#[test]
fn test_get_none_in_store_table() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();

    // Create an in-store counter
    let table = InStoreTable::new(Rc::new(store), "table".to_string());
    table.set::<usize>("value1", None);
    let value = table.get::<usize>(None);
    assert_eq!(value.unwrap(), "value1".to_string());
}

#[test]
fn test_get_many_none_in_store_table() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();

    // Create an in-store counter
    let table = InStoreTable::new(Rc::new(store), "table".to_string());
    let mut entries = HashMap::new();
    entries.insert("key1".to_string(), "value1".to_string());
    entries.insert("key2".to_string(), "value2".to_string());
    table.set_many(entries);
    let value = table.get(Some("key1".to_string()));
    assert_eq!(value.unwrap(), "value1".to_string());
    let value = table.get(Some("key2".to_string()));
    assert_eq!(value.unwrap(), "value2".to_string());

    let values = table.get_many(vec!["key1".to_string(), "key2".to_string()]);
    for (key, value) in values.iter() {
        println!(" key:{} value:{}", key, value);
    }
    assert_eq!(values.get("tablekey1"), Some(&"value1".to_string()));
    assert_eq!(values.get("tablekey2"), Some(&"value2".to_string()));
}

#[test]
fn test_get_some_in_store_table() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let _ = store.init();

    // Create an in-store counter
    let table = InStoreTable::new(Rc::new(store), "table".to_string());
    table.set("value1", Some("suffix1".to_string()));
    let value = table.get(Some("suffix1".to_string()));
    assert_eq!(value.unwrap(), "value1".to_string());
}
