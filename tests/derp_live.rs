use std::io::{Read, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use tailscale_esp32::derp::{DerpClient, Event};
use tailscale_esp32::key::{Node, PrivateKey};

struct OpenSslTls {
    child: Child,
    input: ChildStdin,
    output: ChildStdout,
}

impl OpenSslTls {
    fn connect(host: &str) -> std::io::Result<Self> {
        let mut child = Command::new("openssl")
            .args([
                "s_client",
                "-quiet",
                "-verify_return_error",
                "-verify_hostname",
                host,
                "-CApath",
                "/etc/ssl/certs",
                "-connect",
                &format!("{host}:443"),
                "-servername",
                host,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self {
            input: child.stdin.take().expect("piped child stdin"),
            output: child.stdout.take().expect("piped child stdout"),
            child,
        })
    }
}

impl Read for OpenSslTls {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.output.read(buffer)
    }
}

impl Write for OpenSslTls {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.input.write(buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.input.flush()
    }
}

impl Drop for OpenSslTls {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
#[ignore = "requires internet access and the openssl command"]
fn authenticates_with_a_live_tailscale_derp_server() {
    let host = std::env::var("DERP_HOST").unwrap_or_else(|_| "derp1.tailscale.com".into());
    let transport = OpenSslTls::connect(&host).unwrap();
    let private_key = PrivateKey::<Node>::from_bytes([0x42; 32]);
    let mut client = DerpClient::connect(transport, &host, private_key).unwrap();
    assert!(matches!(client.receive().unwrap(), Event::ServerInfo(_)));
    client.send_ping(*b"esp32der").unwrap();
    loop {
        if let Event::Pong(payload) = client.receive().unwrap() {
            assert_eq!(payload, *b"esp32der");
            break;
        }
    }
}
