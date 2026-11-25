mod support;

use serde_json::json;
use std::{
    io::{Read, Write},
    time::{Duration, Instant},
};
use support::{App, Server, runtime_lock};

#[test]
fn a_closed_vless_peer_reports_response_progress_direction_and_selected_route() {
    let _serial = runtime_lock();
    // Accept the VLESS request, then close after only one response header byte.
    let node = Server::spawn(|mut stream| {
        let mut request = [0; 4096];
        assert!(stream.read(&mut request).unwrap() > 0);
        stream.write_all(&[0]).unwrap();
    });
    let app = App::new();
    app.import("diagnostic fixture", vec![json!({
        "type":"vless", "tag":"chosen-node", "server":"127.0.0.1", "server_port":node.address.port(),
        "uuid":"00000000-0000-4000-8000-000000000001"
    })]);
    app.service.start().unwrap();
    assert!(support::request(&app.service, "http://192.0.2.1/").is_err());
    let deadline = Instant::now() + Duration::from_secs(2);
    let logs = loop {
        let logs = app.service.logs();
        if logs.contains("stage=vless_response") || Instant::now() >= deadline {
            break logs;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    for field in [
        "stage=relay_download",
        "stage=vless_response",
        "received=1 expected=2",
        "node-0",
        "192.0.2.1:80",
        "UnexpectedEof",
    ] {
        assert!(logs.contains(field), "missing {field}: {logs}");
    }
    assert!(
        !logs.contains("00000000-0000-4000-8000-000000000001"),
        "credentials in logs"
    );
}
