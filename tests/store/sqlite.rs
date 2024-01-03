use accumulators::store::{
    sqlite::SQLiteStore,
    InStoreCounter, Store, {InStoreTable, SubKey},
};
use std::{collections::HashMap, sync::Arc};

#[tokio::test]
async fn set_and_get_value() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let key_value = (
        "6b9b77f2-a893-48bf-a52a-d5be5d0aaba3:RootHash",
        "0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804",
    );
    store.set(key_value.0, key_value.1).await.unwrap();

    store.set("key", "value").await.unwrap();
    let value = store.get("key").await.unwrap();
    assert_eq!(value.unwrap(), "value");

    let value1 = store.get(key_value.0).await;
    assert_eq!(value1.unwrap(), Some(key_value.1.to_owned()));
}

#[tokio::test]
async fn set_and_get_many_values() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let mut entries = HashMap::new();
    entries.insert("key1".to_string(), "value1".to_string());
    entries.insert("key2".to_string(), "value2".to_string());

    store.set_many(entries).await.unwrap();

    let values = store.get_many(vec!["key1", "key2"]).await.unwrap();

    assert_eq!(values.get("key1"), Some(&"value1".to_string()));
}

#[tokio::test]
async fn get_many_values_in_correct_order() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let mut entries = HashMap::new();
    entries.insert("a".to_string(), "value1".to_string());
    entries.insert("b".to_string(), "value2".to_string());
    entries.insert("10".to_string(), "value3".to_string());
    entries.insert("5".to_string(), "value4".to_string());

    store.set_many(entries).await.unwrap();

    let keys = vec!["a", "b", "10", "5"];

    let values = store.get_many(keys).await.unwrap();

    assert_eq!(values.get("a"), Some(&"value1".to_string()));
    assert_eq!(values.get("b"), Some(&"value2".to_string()));
    assert_eq!(values.get("10"), Some(&"value3".to_string()));
    assert_eq!(values.get("5"), Some(&"value4".to_string()));
}

#[tokio::test]
async fn should_delete_a_value() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    store.set("key", "value").await.unwrap();
    store.delete("key").await.unwrap();
    let value = store.get("key").await.unwrap();

    assert_eq!(value, None);
}

#[tokio::test]
async fn test_in_store_counter() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();
    let store = Arc::new(store);

    // Create an in-store counter
    let counter = InStoreCounter::new(store.clone(), "counter".to_string());
    let _ = counter.set(10).await;
    let value = counter.get().await.unwrap();
    assert_eq!(value, 10);
    let newcounter = counter.increment().await.unwrap();
    assert_eq!(newcounter, 11);
}

#[tokio::test]
async fn test_get_none_in_store_table() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let store = Arc::new(store);

    // Create an in-store counter
    let table = InStoreTable::new(store.clone(), "table".to_string());
    table.set("value1", SubKey::None).await.unwrap();
    let value = table.get(SubKey::None).await.unwrap();
    assert_eq!(value.unwrap(), "value1".to_string());
}

#[tokio::test]
async fn test_get_many_none_in_store_table() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let store = Arc::new(store);

    // Create an in-store counter
    let table = InStoreTable::new(store.clone(), "table".to_string());
    let mut entries = HashMap::new();
    entries.insert(SubKey::String("key1".to_string()), "value1".to_string());
    entries.insert(SubKey::String("key2".to_string()), "value2".to_string());
    table.set_many(entries).await.unwrap();
    let value = table.get(SubKey::String("key1".to_string())).await.unwrap();
    assert_eq!(value.unwrap(), "value1".to_string());
    let value = table.get(SubKey::String("key2".to_string())).await.unwrap();
    assert_eq!(value.unwrap(), "value2".to_string());

    let values = table
        .get_many(vec![
            SubKey::String("key1".to_string()),
            SubKey::String("key2".to_string()),
        ])
        .await
        .unwrap();
    assert_eq!(values.get("tablekey1"), Some(&"value1".to_string()));
    assert_eq!(values.get("tablekey2"), Some(&"value2".to_string()));
}

#[tokio::test]
async fn test_get_some_in_store_table() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let store = Arc::new(store);

    // Create an in-store counter
    let table = InStoreTable::new(store.clone(), "table".to_string());
    table
        .set("value1", SubKey::String("suffix1".to_string()))
        .await
        .unwrap();
    let value = table
        .get(SubKey::String("suffix1".to_string()))
        .await
        .unwrap();
    assert_eq!(value.unwrap(), "value1".to_string());
}
