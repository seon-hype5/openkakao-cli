#![cfg(target_os = "windows")]

use openkakao_cli::platform::windows::WindowsBackend;
use openkakao_cli::platform::PlatformProbe;

#[test]
fn production_backend_exposes_only_the_build_selected_capability_surface() {
    let backend = WindowsBackend::default();
    let capabilities = backend.capabilities();

    assert!(capabilities.inspect);
    #[cfg(not(feature = "windows-ui-write"))]
    assert!(!capabilities.send_open_chat);
    #[cfg(feature = "windows-ui-write")]
    assert!(capabilities.send_open_chat);
    assert!(!capabilities.open_chat_by_name);
    assert!(!capabilities.read_visible);
    assert!(!capabilities.watch_unread);
}

#[test]
fn production_backend_debug_contains_no_native_identity() {
    assert_eq!(format!("{:?}", WindowsBackend::default()), "WindowsBackend");
}
