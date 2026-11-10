use aerobox_for_linux::model::Store;
use std::process::Command;

#[test]
fn default_configuration_uses_the_user_config_directory() {
    if let Ok(expected) = std::env::var("AEROBOX_TEST_CONFIG_DIRECTORY") {
        let store = Store::open(None).unwrap();
        assert_eq!(store.dir, std::path::PathBuf::from(expected));
        assert!(store.dir.join("state.json").is_file());
        return;
    }
    let root = tempfile::tempdir().unwrap();
    for configured in [true, false] {
        let config = root
            .path()
            .join(if configured { "custom" } else { "home/.config" });
        let mut child = Command::new(std::env::current_exe().unwrap());
        child
            .args([
                "--exact",
                "default_configuration_uses_the_user_config_directory",
                "--nocapture",
            ])
            .env("HOME", root.path().join("home"))
            .env("XDG_DATA_HOME", root.path().join("data"))
            .env(
                "AEROBOX_TEST_CONFIG_DIRECTORY",
                config.join("AeroBoxForLinux"),
            );
        if configured {
            child.env("XDG_CONFIG_HOME", &config);
        } else {
            child.env_remove("XDG_CONFIG_HOME");
        }
        assert!(child.status().unwrap().success());
    }
    assert!(!root.path().join("data/singbox").exists());
}
