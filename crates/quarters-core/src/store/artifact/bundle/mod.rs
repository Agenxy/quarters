//! Authenticated portable export and import bundles.

mod export;
mod format;
mod import;
mod key;
mod model;

pub use model::{BundleExportReport, BundleHeader, BundleImportReport, ExportKeyReport};

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{export, import};
    use crate::{ArtifactKind, ArtifactName, ArtifactOrigin, SpaceName, Store};
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use tempfile::TempDir;

    static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn whole_tree_phases_do_not_hold_the_management_lock() {
        let _serial = TEST_SERIAL.lock().expect("bundle test serialization");
        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).expect("protect temporary root");
        let store = Store::new(temporary.path().join("store")).expect("valid store");
        for raw in ["source", "unrelated"] {
            store
                .create(SpaceName::parse(raw).expect("valid space"), PathBuf::from("/bin/sh"))
                .expect("create space");
        }
        let source_home = store
            .open(&SpaceName::parse("source").expect("valid source"))
            .expect("open source")
            .home();
        fs::write(source_home.join("payload"), vec![0x5a; 1024 * 1024]).expect("write payload");
        let template = ArtifactName::parse("portable").expect("valid artifact");
        store
            .create_artifact(
                ArtifactKind::Template,
                &SpaceName::parse("source").expect("valid source"),
                template.clone(),
                false,
                ArtifactOrigin::User,
            )
            .expect("create template");
        let key = temporary.path().join("bundle.key");
        store.create_export_key(&key).expect("create key");
        let bundle = temporary.path().join("portable.qbundle");

        let export_barrier = Arc::new(Barrier::new(2));
        export::set_test_barrier(Some(Arc::clone(&export_barrier)));
        std::thread::scope(|scope| {
            let child_store = store.clone();
            let child_key = key.clone();
            let child_bundle = bundle.clone();
            let child_template = template.clone();
            let handle = scope.spawn(move || {
                child_store.export_bundle(ArtifactKind::Template, &child_template, &child_bundle, &child_key)
            });
            export_barrier.wait();
            let unrelated = store
                .open(&SpaceName::parse("unrelated").expect("valid unrelated"))
                .expect("open unrelated");
            let lease = store.lease(&unrelated).expect("acquire lease during export");
            drop(lease);
            export_barrier.wait();
            handle.join().expect("export thread").expect("export bundle");
        });
        export::set_test_barrier(None);

        let imported = ArtifactName::parse("imported").expect("valid import name");
        let plan = store
            .bundle_import_plan(&bundle, &imported, &key)
            .expect("preview import");
        let import_barrier = Arc::new(Barrier::new(2));
        import::set_test_barrier(Some(Arc::clone(&import_barrier)));
        std::thread::scope(|scope| {
            let child_store = store.clone();
            let child_key = key.clone();
            let child_bundle = bundle.clone();
            let child_imported = imported.clone();
            let digest = plan.plan_digest.clone();
            let handle =
                scope.spawn(move || child_store.import_bundle(&child_bundle, &child_imported, &child_key, &digest));
            import_barrier.wait();
            let unrelated = store
                .open(&SpaceName::parse("unrelated").expect("valid unrelated"))
                .expect("open unrelated");
            let lease = store.lease(&unrelated).expect("acquire lease during import");
            drop(lease);
            import_barrier.wait();
            handle.join().expect("import thread").expect("import bundle");
        });
        import::set_test_barrier(None);
    }

    #[test]
    fn source_mutation_aborts_export_without_publication() {
        let _serial = TEST_SERIAL.lock().expect("bundle test serialization");
        let (temporary, store, template, key, bundle) = fixture();
        let artifact = store
            .verify_artifact(ArtifactKind::Template, &template)
            .expect("verified template");
        let export_barrier = Arc::new(Barrier::new(2));
        export::set_test_barrier(Some(Arc::clone(&export_barrier)));
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| store.export_bundle(ArtifactKind::Template, &template, &bundle, &key));
            export_barrier.wait();
            fs::write(artifact.home().join("payload"), b"changed during export").expect("mutate source artifact");
            export_barrier.wait();
            assert!(handle.join().expect("export thread").is_err());
        });
        export::set_test_barrier(None);
        assert!(!bundle.exists());
        drop(temporary);
    }

    #[test]
    fn bundle_mutation_between_passes_aborts_import_without_publication() {
        let _serial = TEST_SERIAL.lock().expect("bundle test serialization");
        let (_temporary, store, template, key, bundle) = fixture();
        store
            .export_bundle(ArtifactKind::Template, &template, &bundle, &key)
            .expect("export bundle");
        let destination = ArtifactName::parse("imported").expect("valid destination");
        let preview = store
            .bundle_import_plan(&bundle, &destination, &key)
            .expect("preview import");
        let import_barrier = Arc::new(Barrier::new(2));
        import::set_test_barrier(Some(Arc::clone(&import_barrier)));
        std::thread::scope(|scope| {
            let handle = scope.spawn(|| store.import_bundle(&bundle, &destination, &key, &preview.plan_digest));
            import_barrier.wait();
            OpenOptions::new()
                .append(true)
                .open(&bundle)
                .and_then(|mut file| file.write_all(b"mutation"))
                .expect("mutate retained bundle");
            import_barrier.wait();
            assert!(handle.join().expect("import thread").is_err());
        });
        import::set_test_barrier(None);
        assert!(store.verify_artifact(ArtifactKind::Template, &destination).is_err());
    }

    #[test]
    fn post_commit_failures_report_warnings_and_keep_publications() {
        let _serial = TEST_SERIAL.lock().expect("bundle test serialization");
        let _reset = FaultReset;
        let (temporary, store, template, key, bundle) = fixture();
        super::key::set_test_publication_faults(0b10);
        let exported = store
            .export_bundle(ArtifactKind::Template, &template, &bundle, &key)
            .expect("committed export");
        assert!(exported.publication_warning.is_some());
        assert!(bundle.is_file());
        super::key::set_test_publication_faults(0);

        let imported = ArtifactName::parse("imported-warning").expect("valid destination");
        let preview = store
            .bundle_import_plan(&bundle, &imported, &key)
            .expect("preview import");
        super::import::set_test_import_sync_failure(true);
        let report = store
            .import_bundle(&bundle, &imported, &key, &preview.plan_digest)
            .expect("committed import");
        assert!(report.publication_warning.is_some());
        assert!(store.verify_artifact(ArtifactKind::Template, &imported).is_ok());
        super::import::set_test_import_sync_failure(false);

        let second_key = temporary.path().join("warning.key");
        super::key::set_test_publication_faults(0b01);
        let key_report = store.create_export_key(&second_key).expect("committed key");
        assert!(key_report.publication_warning.is_some());
        assert!(second_key.is_file());
    }

    struct FaultReset;

    impl Drop for FaultReset {
        fn drop(&mut self) {
            super::key::set_test_publication_faults(0);
            super::import::set_test_import_sync_failure(false);
        }
    }

    fn fixture() -> (TempDir, Store, ArtifactName, PathBuf, PathBuf) {
        let temporary = TempDir::new().expect("temporary directory");
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).expect("protect temporary root");
        let store = Store::new(temporary.path().join("store")).expect("valid store");
        let source = SpaceName::parse("source").expect("valid source");
        store
            .create(source.clone(), PathBuf::from("/bin/sh"))
            .expect("create source");
        let source_home = store.open(&source).expect("open source").home();
        fs::write(source_home.join("payload"), vec![0x5a; 1024 * 1024]).expect("write payload");
        let template = ArtifactName::parse("portable").expect("valid artifact");
        store
            .create_artifact(
                ArtifactKind::Template,
                &source,
                template.clone(),
                false,
                ArtifactOrigin::User,
            )
            .expect("create template");
        let key = temporary.path().join("bundle.key");
        store.create_export_key(&key).expect("create key");
        let bundle = temporary.path().join("portable.qbundle");
        (temporary, store, template, key, bundle)
    }
}
