//! Real-store research controls; these SQL fixtures are not activated in production.
#![cfg(feature = "sqlite")]
#![forbid(unsafe_code)]

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aunsorm_jwt::{JtiStore, SqliteJtiStore};
use rusqlite::{params, Connection, TransactionBehavior};

const FENCE: &str = include_str!("data/replay_fence.sql");
const ROLLBACK: &str = include_str!("data/replay_rollback.sql");

fn cutover(path: &Path) {
    let mut connection = Connection::open(path).unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(FENCE).unwrap();
    transaction.commit().unwrap();
}

fn count(connection: &Connection, table: &str) -> i64 {
    // Only test-owned fixed identifiers, never untrusted SQL interpolation.
    let query = match table {
        "jti" => "SELECT COUNT(*) FROM jti",
        "legacy" => "SELECT COUNT(*) FROM jti_legacy_tombstones",
        "canonical" => "SELECT COUNT(*) FROM jti_canonical_fixture",
        _ => panic!("unknown fixture table"),
    };
    connection.query_row(query, [], |row| row.get(0)).unwrap()
}

#[test]
fn version_marker_alone_does_not_fence_the_actual_old_writer() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("marker.sqlite");
    let old = SqliteJtiStore::open(&path).unwrap();
    assert!(old.check_and_insert("spent", None).unwrap());
    Connection::open(&path)
        .unwrap()
        .pragma_update(None, "user_version", 2)
        .unwrap();
    let reopened = SqliteJtiStore::open(&path).unwrap();
    assert!(reopened.check_and_insert("after-marker", None).unwrap());
    assert!(!old.check_and_insert("spent", None).unwrap());
}

#[test]
fn already_open_and_reopened_old_writers_cannot_insert_through_the_fence() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fenced.sqlite");
    let old = SqliteJtiStore::open(&path).unwrap();
    assert!(old.check_and_insert("spent", None).unwrap());
    cutover(&path);
    let error = old
        .check_and_insert("new-old-worker-token", None)
        .unwrap_err();
    assert!(error.to_string().contains("legacy insert rejected"));
    // Actual CREATE INDEX validates the view before IF NOT EXISTS can reuse
    // the old global index. Startup fails explicitly; no empty table appears.
    let error = match SqliteJtiStore::open(&path) {
        Err(error) => error,
        Ok(_) => panic!("old store unexpectedly opened a fenced view"),
    };
    assert!(error.to_string().contains("views may not be indexed"));
    let connection = Connection::open(&path).unwrap();
    assert_eq!(count(&connection, "legacy"), 1);
    assert_eq!(count(&connection, "jti"), 1);
    assert_eq!(count(&connection, "canonical"), 0);
    let kind: String = connection
        .query_row(
            "SELECT type FROM sqlite_master WHERE name = 'jti'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(kind, "view");
}

#[test]
fn expired_cleanup_from_the_actual_old_store_cannot_erase_tombstones() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("cleanup.sqlite");
    let old = SqliteJtiStore::open(&path).unwrap();
    let connection = Connection::open(&path).unwrap();
    connection
        .execute(
            "INSERT INTO jti(jti, expires_at) VALUES ('retained-history', 0)",
            [],
        )
        .unwrap();
    cutover(&path);
    let error = old.purge_expired(SystemTime::now()).unwrap_err();
    assert!(error.to_string().contains("legacy delete rejected"));
    assert_eq!(count(&connection, "legacy"), 1);
    // check_and_insert runs cleanup first; that path must fail too.
    assert!(old.check_and_insert("new-token", None).is_err());
    assert_eq!(count(&connection, "legacy"), 1);
}

#[test]
fn aborted_cutover_rolls_back_schema_and_preserves_consumption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("abort.sqlite");
    let old = SqliteJtiStore::open(&path).unwrap();
    assert!(old.check_and_insert("spent-before-abort", None).unwrap());
    let mut connection = Connection::open(&path).unwrap();
    {
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction.execute_batch(FENCE).unwrap();
        assert!(transaction
            .execute("INSERT INTO nonexistent_fixture VALUES (1)", [])
            .is_err());
        // Dropping the uncommitted real transaction rolls back all DDL.
    }
    assert_eq!(count(&connection, "jti"), 1);
    assert!(!old.check_and_insert("spent-before-abort", None).unwrap());
    assert!(old.check_and_insert("new-after-abort", None).unwrap());
    let canonical_tables: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'jti_canonical_fixture'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(canonical_tables, 0);
}

#[test]
fn conservative_rollback_keeps_post_cutover_consumption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("rollback.sqlite");
    let old = SqliteJtiStore::open(&path).unwrap();
    assert!(old.check_and_insert("legacy-spent", None).unwrap());
    cutover(&path);
    let mut connection = Connection::open(&path).unwrap();
    // This is a canonical-row fixture, not a new verifier/store API. Its legacy
    // projection is retained explicitly; it cannot be decoded from old keys.
    connection.execute(
        "INSERT INTO jti_canonical_fixture(identity, legacy_projection, expires_at) VALUES (?1, ?2, NULL)",
        params![&[7_u8; 32][..], "canonical-post-cutover"],
    ).unwrap();
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(ROLLBACK).unwrap();
    transaction.commit().unwrap();
    let reopened = SqliteJtiStore::open(&path).unwrap();
    assert!(!reopened.check_and_insert("legacy-spent", None).unwrap());
    assert!(!reopened
        .check_and_insert("canonical-post-cutover", None)
        .unwrap());
    assert_eq!(count(&connection, "canonical"), 1);
    assert!(reopened.check_and_insert("clean-new-token", None).unwrap());
}

#[test]
fn rollback_projection_keeps_longest_or_permanent_collision_retention() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("retention.sqlite");
    let old = SqliteJtiStore::open(&path).unwrap();
    let now = SystemTime::now();
    let seconds = i64::try_from(now.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap();
    for name in ["finite-collision", "becomes-permanent"] {
        assert!(old
            .check_and_insert(name, Some(now + Duration::from_secs(60)))
            .unwrap());
    }
    assert!(old.check_and_insert("already-permanent", None).unwrap());
    cutover(&path);
    let mut connection = Connection::open(&path).unwrap();
    for (identity, projection, expiry) in [
        (1_u8, "finite-collision", Some(seconds + 30)),
        (2, "finite-collision", Some(seconds + 120)),
        (3, "becomes-permanent", None),
        (4, "already-permanent", Some(seconds + 120)),
    ] {
        connection.execute(
            "INSERT INTO jti_canonical_fixture(identity, legacy_projection, expires_at) VALUES (?1, ?2, ?3)",
            params![&[identity; 32][..], projection, expiry],
        ).unwrap();
    }
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    transaction.execute_batch(ROLLBACK).unwrap();
    transaction.commit().unwrap();
    for (name, expected) in [
        ("finite-collision", Some(seconds + 120)),
        ("becomes-permanent", None),
        ("already-permanent", None),
    ] {
        let expiry: Option<i64> = connection
            .query_row("SELECT expires_at FROM jti WHERE jti = ?1", [name], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(expiry, expected);
        assert!(!old.check_and_insert(name, None).unwrap());
    }
    assert_eq!(count(&connection, "canonical"), 4);
}
