#![cfg(target_os = "windows")]

use openkakao_cli::platform::windows::WindowsBackend;
use openkakao_cli::platform::PlatformProbe;

#[test]
fn production_backend_keeps_send_disabled_without_verified_identity_and_selector() {
    let backend = WindowsBackend::default();
    let capabilities = backend.capabilities();

    assert!(capabilities.inspect);
    assert!(!capabilities.send_open_chat);
    assert!(!capabilities.open_chat_by_name);
    assert!(!capabilities.read_visible);
    assert!(!capabilities.watch_unread);
}

#[test]
fn production_backend_debug_contains_no_native_identity() {
    assert_eq!(format!("{:?}", WindowsBackend::default()), "WindowsBackend");
}
