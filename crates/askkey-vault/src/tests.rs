use super::*;

const NAMESPACE: &str = "com.sudohg.askkey.vault.test";

fn component(name: &str, variable: Option<&str>, value: Option<&str>) -> ComponentInput {
    ComponentInput {
        name: name.into(),
        environment_variable: variable.map(Into::into),
        value: value.map(Into::into),
    }
}

fn synthetic(name: &str) -> NewCredential {
    NewCredential {
        name: name.into(),
        permission: Permission::Ask,
        usage_instructions: "Synthetic test credential.".into(),
        group: Some("Testing".into()),
        components: vec![
            component("user", Some("SYNTH_USER"), Some("synthetic-user")),
            component(
                "password",
                Some("SYNTH_PASSWORD"),
                Some("synthetic-password"),
            ),
        ],
        expires_at: None,
    }
}

#[test]
fn creates_reopens_and_reads_values() {
    let directory = tempfile::tempdir().unwrap();
    let id = {
        let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
        vault.create(synthetic("Test NAS")).unwrap().id
    };
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let credential = vault.get(&id).unwrap();
    assert_eq!(credential.name, "Test NAS");
    assert_eq!(credential.permission, Permission::Ask);
    assert_eq!(credential.group.as_deref(), Some("Testing"));
    let values = vault.values(&id).unwrap();
    assert_eq!(values[1].as_str(), "synthetic-password");
    assert_eq!(vault.find_by_name("test nas").unwrap().unwrap().id, id);
}

#[test]
fn stored_rows_do_not_contain_plaintext() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    vault.create(synthetic("Plaintext Probe")).unwrap();
    drop(vault);
    let mut bytes = std::fs::read(directory.path().join("credentials.db")).unwrap();
    if let Ok(wal) = std::fs::read(directory.path().join("credentials.db-wal")) {
        bytes.extend(wal);
    }
    let haystack = String::from_utf8_lossy(&bytes);
    assert!(!haystack.contains("synthetic-password"));
    assert!(!haystack.contains("Plaintext Probe"));
}

#[test]
fn names_are_unique_case_insensitively() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    vault.create(synthetic("GitHub")).unwrap();
    assert!(matches!(
        vault.create(synthetic("github")),
        Err(VaultError::NameTaken)
    ));
}

#[test]
fn update_keeps_values_given_without_replacement() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let id = vault.create(synthetic("Server")).unwrap().id;
    vault
        .update(
            &id,
            CredentialUpdate {
                name: "Server".into(),
                usage_instructions: String::new(),
                group: None,
                components: vec![
                    component("user", Some("SYNTH_USER"), Some("changed-user")),
                    component("password", None, None),
                ],
                expires_at: None,
            },
        )
        .unwrap();
    let values = vault.values(&id).unwrap();
    assert_eq!(values[0].as_str(), "changed-user");
    assert_eq!(values[1].as_str(), "synthetic-password");
    let credential = vault.get(&id).unwrap();
    assert_eq!(credential.components[1].environment_variable, None);
    assert_eq!(credential.group, None);
}

#[test]
fn tampered_permission_fails_authentication() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let id = vault.create(synthetic("Guarded")).unwrap().id;
    vault
        .connection()
        .execute(
            "UPDATE credentials SET permission = 'allow' WHERE id = ?1",
            [&id],
        )
        .unwrap();
    assert!(matches!(vault.get(&id), Err(VaultError::Authentication)));
    assert!(matches!(vault.values(&id), Err(VaultError::Authentication)));
}

#[test]
fn set_permission_is_authenticated() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let id = vault.create(synthetic("Toggle")).unwrap().id;
    assert_eq!(
        vault
            .set_permission(&id, Permission::Hidden)
            .unwrap()
            .permission,
        Permission::Hidden
    );
    assert_eq!(vault.values(&id).unwrap()[0].as_str(), "synthetic-user");
}

#[test]
fn missing_key_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    Vault::open(directory.path(), NAMESPACE)
        .unwrap()
        .create(synthetic("Kept"))
        .unwrap();
    std::fs::remove_file(directory.path().join("vault.key")).unwrap();
    assert!(matches!(
        Vault::open(directory.path(), NAMESPACE),
        Err(VaultError::MissingKey)
    ));
    // The existing database is untouched.
    assert!(directory.path().join("credentials.db").exists());
}

#[test]
fn missing_database_fails_closed() {
    let directory = tempfile::tempdir().unwrap();
    drop(Vault::open(directory.path(), NAMESPACE).unwrap());
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(directory.path().join(format!("credentials.db{suffix}")));
    }
    assert!(matches!(
        Vault::open(directory.path(), NAMESPACE),
        Err(VaultError::MissingDatabase)
    ));
}

#[test]
fn wrong_namespace_cannot_open() {
    let directory = tempfile::tempdir().unwrap();
    drop(Vault::open(directory.path(), NAMESPACE).unwrap());
    assert!(matches!(
        Vault::open(directory.path(), "another.namespace"),
        Err(VaultError::Authentication)
    ));
}

#[test]
fn finishes_interrupted_creation_of_an_empty_library() {
    let directory = tempfile::tempdir().unwrap();
    drop(Vault::open(directory.path(), NAMESPACE).unwrap());
    // Simulate a crash after the database was published but before the key
    // was promoted.
    std::fs::rename(
        directory.path().join("vault.key"),
        directory.path().join("vault.key.pending"),
    )
    .unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    assert!(vault.list().unwrap().is_empty());
    assert!(directory.path().join("vault.key").exists());
}

#[test]
fn access_records_round_trip() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    vault
        .record_access(AccessRecord {
            at: 0,
            credential_names: vec!["Test".into()],
            executable: "git.exe".into(),
            caller_name: Some("Synthetic agent".into()),
            decision: AccessDecision::Approved,
        })
        .unwrap();
    let records = vault.access_records(10).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].executable, "git.exe");
    assert!(records[0].at > 0);
}

#[test]
fn rejects_invalid_input() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let mut missing_value = synthetic("Missing");
    missing_value.components[0].value = None;
    assert!(vault.create(missing_value).is_err());
    let mut bad_variable = synthetic("Bad");
    bad_variable.components[0].environment_variable = Some("NOT-VALID".into());
    assert!(vault.create(bad_variable).is_err());
}

#[test]
fn revision_changes_on_every_write() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let created = vault.create(synthetic("Revisioned")).unwrap();
    assert_eq!(vault.get(&created.id).unwrap().revision, created.revision);
    let allowed = vault
        .set_permission(&created.id, Permission::Allow)
        .unwrap();
    assert_ne!(allowed.revision, created.revision);
    let mut update = CredentialUpdate {
        name: "Revisioned".into(),
        usage_instructions: String::new(),
        group: None,
        components: vec![component("user", Some("SYNTH_USER"), None)],
        expires_at: None,
    };
    let edited = vault.update(&created.id, update.clone()).unwrap();
    assert_ne!(edited.revision, allowed.revision);
    update.components[0].value = Some("synthetic-other".into());
    assert_ne!(
        vault.update(&created.id, update).unwrap().revision,
        edited.revision
    );
}

#[test]
fn names_are_unique_under_full_case_folding() {
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    let id = vault.create(synthetic("Stra\u{df}e")).unwrap().id;
    assert!(matches!(
        vault.create(synthetic("STRASSE")),
        Err(VaultError::NameTaken)
    ));
    assert_eq!(vault.find_by_name("strasse").unwrap().unwrap().id, id);
}

#[test]
fn rows_keyed_by_the_first_preview_are_rekeyed() {
    let directory = tempfile::tempdir().unwrap();
    let id = {
        let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
        let id = vault.create(synthetic("Stra\u{df}e")).unwrap().id;
        let mut raw = vault.raw(&id).unwrap();
        raw.name_key = vault.keys.name_key(&legacy_normalized_name("Stra\u{df}e"));
        raw.sign(&vault.keys);
        vault.write_row(&raw, false).unwrap();
        assert!(vault.find_by_name("STRASSE").unwrap().is_none());
        id
    };
    let vault = Vault::open(directory.path(), NAMESPACE).unwrap();
    assert_eq!(vault.find_by_name("STRASSE").unwrap().unwrap().id, id);
    assert_eq!(vault.list().unwrap().len(), 1);
}
