use super::*;

fn problems(source: &str) -> Vec<String> {
    let parsed = syn::parse_file(source).unwrap();
    let mut scope = Scope {
        module: "crate".into(),
        ..Scope::default()
    };
    item_names(&parsed.items, &mut scope);
    let globals = Names::new();
    let dropped_fields = dropped_fields(&parsed.items);
    let mut audit = Audit {
        scope,
        globals: &globals,
        file: Path::new("fixture.rs"),
        problems: BTreeSet::new(),
        owned: 0,
        awaited: 0,
        boundary: false,
        owner_type: None,
        dropped_fields: &dropped_fields,
        owned_sites: BTreeSet::new(),
    };
    for item in &parsed.items {
        audit.visit_item(item);
    }
    audit
        .problems
        .into_iter()
        .map(|(_, message)| message)
        .collect()
}

#[test]
fn catches_function_module_type_and_extern_crate_aliases() {
    let found = problems(
        r#"
        extern crate tokio as executor;
        use executor::task::{self as tasks, spawn as launch};
        use executor::runtime::Handle as H;
        type Runtime = H;
        async fn run(runtime: &Runtime) {
            launch(async {});
            tasks::spawn(async {});
            runtime.spawn(async {});
            let f = executor::spawn;
            f(async {});
        }
    "#,
    );
    assert_eq!(found.len(), 4, "{found:?}");
}

#[test]
fn cfg_test_is_excluded_but_alternative_production_feature_is_checked() {
    let found = problems(
        r#"
        #[cfg(test)] fn test_only() { tokio::spawn(async {}); }
        #[cfg(all(feature = "peer", test))] fn also_test() { tokio::spawn(async {}); }
        #[cfg(any(test, feature = "peer"))] fn production_too() { tokio::spawn(async {}); }
        #[cfg(not(test))] fn production() { tokio::spawn(async {}); }
        struct Foo;
        impl Foo { #[cfg(test)] fn helper() { tokio::spawn(async {}); } }
    "#,
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn owned_joinset_and_abort_guard_are_allowed_but_nested_task_is_not() {
    let found = problems(
        r#"
        use tokio::task::JoinSet as Set;
        use tokio_util::task::AbortOnDropHandle as Guard;
        async fn run() {
            let mut jobs = Set::new();
            jobs.spawn(async {});
            while jobs.join_next().await.is_some() {}
            let _owned = Guard::new(tokio::spawn(async { tokio::spawn(async {}); }));
            jobs.detach_all();
        }
        async fn borrowed(jobs: &mut Set<()>) { jobs.spawn(async {}); }
    "#,
    );
    assert_eq!(found.len(), 3, "{found:?}");
}

#[test]
fn awaits_only_allow_blocking_work_not_nested_async_spawns() {
    let found = problems(
        r#"
        async fn run() {
            tokio::task::spawn_blocking(|| 1).await.unwrap();
            tokio::spawn(async {}).await.unwrap();
            tokio::task::spawn_blocking(|| { tokio::spawn(async {}); }).await.unwrap();
            tokio::task::spawn_blocking(|| 1);
        }
    "#,
    );
    assert_eq!(found.len(), 3, "{found:?}");
}

#[test]
fn scans_launches_inside_select_and_local_aliases() {
    let found = problems(
        r#"
        async fn run() {
            use tokio::spawn as launch;
            tokio::select! { _ = stop() => {}, _ = ready() => { launch(async {}); } }
            custom!(tokio::spawn(async {}));
        }
    "#,
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn finds_runtime_handles_in_map_and_local_bindings() {
    let found = problems(
        r#"
        fn run() {
            let runtime = tokio::runtime::Handle::current();
            runtime.spawn(async {});
            tokio::runtime::Handle::try_current().ok().map(|handle| handle.spawn(async {}));
        }
    "#,
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn a_drop_only_owns_the_exact_field_and_does_not_hide_other_spawns() {
    let found = problems(
        r#"
        struct Owner { task: Option<tokio::task::JoinHandle<()>>, loose: tokio::task::JoinHandle<()> }
        impl Drop for Owner {
            fn drop(&mut self) { if let Some(task) = self.task.take() { task.abort(); } }
        }
        fn create() -> Owner {
            tokio::spawn(async {});
            let task = tokio::spawn(async { tokio::spawn(async {}); });
            let loose = tokio::spawn(async {});
            Owner { task: Some(task), loose }
        }
    "#,
    );
    assert_eq!(found.len(), 3, "{found:?}");
}

#[test]
fn tuple_drop_and_abort_handle_retention_are_recognized() {
    let found = problems(
        r#"
        struct Owner(tokio::task::AbortHandle);
        impl Drop for Owner { fn drop(&mut self) { self.0.abort(); } }
        impl Owner { fn new() -> Self {
            let task = tokio::spawn(async {});
            Self(task.abort_handle())
        } }
    "#,
    );
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn unrelated_spawn_in_initializer_does_not_become_owned() {
    let found = problems(
        r#"
        struct Owner(tokio::task::AbortHandle);
        impl Drop for Owner { fn drop(&mut self) { self.0.abort(); } }
        fn create(task: tokio::task::JoinHandle<()>) -> Owner {
            Owner({ tokio::spawn(async {}); task.abort_handle() })
        }
    "#,
    );
    assert_eq!(found.len(), 1, "{found:?}");
}

#[test]
fn forgetting_a_local_set_or_guard_is_rejected() {
    let found = problems(
        r#"
        fn run() {
            let set = tokio::task::JoinSet::new();
            let guard = tokio_util::task::AbortOnDropHandle::new(tokio::spawn(async {}));
            std::mem::forget(set);
            core::mem::forget(guard);
        }
    "#,
    );
    assert_eq!(found.len(), 2, "{found:?}");
}

#[test]
fn walks_only_declared_production_modules_and_follows_path_attributes() {
    let unique = format!(
        "aerobox-task-owner-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let root = std::env::temp_dir().join(unique);
    struct Directory(PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    std::fs::create_dir_all(root.join("live")).unwrap();
    let _cleanup = Directory(root.clone());
    std::fs::write(root.join("lib.rs"), "#[cfg(test)] mod never_read; #[path=\"real.rs\"] mod live; pub use tokio::spawn as launch;").unwrap();
    std::fs::write(
        root.join("real.rs"),
        "use crate::launch as go; fn run() { go(async {}); }",
    )
    .unwrap();
    let error = check(&root.join("lib.rs")).unwrap_err();
    assert!(error.contains("real.rs:1: tokio::spawn"), "{error}");
    std::fs::write(root.join("real.rs"), "#[cfg(test)] mod ignored;").unwrap();
    assert_eq!(check(&root.join("lib.rs")).unwrap(), 2);
}
