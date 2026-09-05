//! The mandatory lookup service end to end, in process: a plain-HTTP relay
//! (the same server `iroh-relay --dev` runs), a pkarr store behind a
//! secret-prefix gate that behaves like the documented Caddy `handle_path`
//! block, a server that must publish through it, and a client that resolves
//! the server through it with **no relay hints** — the standard iroh dial.

use anyhow::{Context, Result};
use flexaccess_iroh::endpoint::{EndpointOptions, create_endpoint, endpoint_builder};
use flexaccess_iroh::lookup::LookupSecret;
use flexaccess_iroh::relay::{RelayConfig, RelaySettings};
use iroh::endpoint::QuicTransportConfig;
use iroh::{EndpointAddr, SecretKey};
use iroh_relay::server::{RelayConfig as RelayServerConfig, Server, ServerConfig};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const ALPN: &[u8] = b"flexaccess-iroh/lookup-test";

/// A pkarr store gated by a secret path prefix, the way the production
/// reverse proxy gates `iroh-dns-server`: `PUT/GET /<secret>/pkarr/<key>`
/// are served, everything else is a 404 with no hint of why.
struct GatedPkarr {
    url: String,
    records: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    rejected: Arc<Mutex<u32>>,
    task: JoinHandle<()>,
}

impl GatedPkarr {
    async fn spawn(secret: &LookupSecret) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let url = format!("http://{}", listener.local_addr()?);
        let records: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::default();
        let rejected: Arc<Mutex<u32>> = Arc::default();
        let prefix = format!("/{secret}/pkarr/");
        let task = tokio::spawn({
            let records = records.clone();
            let rejected = rejected.clone();
            async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let records = records.clone();
                    let rejected = rejected.clone();
                    let prefix = prefix.clone();
                    tokio::spawn(async move {
                        let _ = serve_one(stream, &prefix, &records, &rejected).await;
                    });
                }
            }
        });
        Ok(Self {
            url,
            records,
            rejected,
            task,
        })
    }

    fn record(&self, endpoint_id: &iroh::EndpointId) -> Option<Vec<u8>> {
        self.records.lock().unwrap().get(&endpoint_id.to_z32()).cloned()
    }

    fn rejected(&self) -> u32 {
        *self.rejected.lock().unwrap()
    }
}

impl Drop for GatedPkarr {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One HTTP/1.1 request, then close.
async fn serve_one(
    stream: tokio::net::TcpStream,
    prefix: &str,
    records: &Mutex<HashMap<String, Vec<u8>>>,
    rejected: &Mutex<u32>,
) -> Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or_default().to_string();
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .split_once(':')
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
            .map(|(_, value)| value.trim())
        {
            content_length = value.parse().context("content-length")?;
        }
    }
    let mut body = vec![0u8; content_length];
    reader.read_exact(&mut body).await?;

    let (status, payload): (&str, Vec<u8>) = match path.strip_prefix(prefix) {
        Some(key) if method == "PUT" => {
            records.lock().unwrap().insert(key.to_string(), body);
            ("204 No Content", Vec::new())
        }
        Some(key) if method == "GET" => match records.lock().unwrap().get(key) {
            Some(record) => ("200 OK", record.clone()),
            None => ("404 Not Found", Vec::new()),
        },
        _ => {
            *rejected.lock().unwrap() += 1;
            ("404 Not Found", Vec::new())
        }
    };
    let mut stream = reader.into_inner();
    stream
        .write_all(
            format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                payload.len()
            )
            .as_bytes(),
        )
        .await?;
    stream.write_all(&payload).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn spawn_relay() -> Result<(Server, String)> {
    let bind: SocketAddr = (Ipv4Addr::LOCALHOST, 0).into();
    let mut config = ServerConfig::default();
    config.relay = Some(RelayServerConfig::new(bind));
    let server = Server::spawn(config).await?;
    let url = format!("http://{}", server.http_addr().context("relay http addr")?);
    Ok((server, url))
}

fn settings(relay_url: &str, lookup_url: &str, secret: &LookupSecret) -> RelaySettings {
    RelaySettings {
        relay_urls: vec![relay_url.to_string()],
        relay_auth_token: None,
        lookup_url: Some(lookup_url.to_string()),
        lookup_secret: Some(secret.to_string()),
    }
}

fn options(publish_address: bool) -> EndpointOptions {
    EndpointOptions {
        transport_config: QuicTransportConfig::builder().build(),
        publish_address,
        relay_only: true,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn server_publishes_through_the_gate_and_a_client_dials_by_id_alone() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let (_relay, relay_url) = spawn_relay().await?;
    let secret = LookupSecret::generate();
    let lookup = GatedPkarr::spawn(&secret).await?;
    let relay_config = RelayConfig::resolve(settings(&relay_url, &lookup.url, &secret))?;

    let server_key = SecretKey::generate();
    let server_id = server_key.public();
    let server = create_endpoint(
        &relay_config,
        endpoint_builder(&relay_config, options(true))
            .alpns(vec![ALPN.to_vec()])
            .secret_key(server_key),
        true,
    )
    .await?;
    let record = lookup
        .record(&server_id)
        .context("server record missing from the lookup store after creation")?;
    assert!(!record.is_empty());
    assert_eq!(lookup.rejected(), 0, "the right secret never hits the gate");

    let accept = tokio::spawn({
        let server = server.clone();
        async move {
            let incoming = server.accept().await.context("server closed")?;
            let conn = incoming.await?;
            let (mut send, mut recv) = conn.accept_bi().await?;
            let buf = recv.read_to_end(64).await?;
            send.write_all(&buf).await?;
            send.finish()?;
            conn.closed().await;
            anyhow::Ok(buf)
        }
    });

    let client = create_endpoint(
        &relay_config,
        endpoint_builder(&relay_config, options(false)),
        false,
    )
    .await?;
    // No relay hint at all: the client must learn the server's relay from the
    // lookup service, exactly as it would after the server moved relays.
    let conn = tokio::time::timeout(
        Duration::from_secs(15),
        client.connect(EndpointAddr::new(server_id), ALPN),
    )
    .await
    .context("dial by id alone timed out: the lookup record was not resolved")??;
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"via lookup").await?;
    send.finish()?;
    let echoed = recv.read_to_end(64).await?;
    assert_eq!(echoed, b"via lookup");
    conn.close(0u32.into(), b"done");
    assert_eq!(accept.await??, b"via lookup");
    assert!(lookup.rejected() == 0);

    client.close().await;
    server.close().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_server_with_the_wrong_secret_does_not_start() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let (_relay, relay_url) = spawn_relay().await?;
    let lookup = GatedPkarr::spawn(&LookupSecret::generate()).await?;
    // Well-formed (valid checksum), just not the service's secret: only the
    // gate can tell, and it answers 404.
    let wrong = LookupSecret::generate();
    let relay_config = RelayConfig::resolve(settings(&relay_url, &lookup.url, &wrong))?;

    let err = create_endpoint(
        &relay_config,
        endpoint_builder(&relay_config, options(true))
            .alpns(vec![ALPN.to_vec()])
            .secret_key(SecretKey::generate()),
        true,
    )
    .await
    .err()
    .context("a rejected publish must fail endpoint creation")?;
    let msg = format!("{err:#}");
    assert!(
        msg.contains("Failed to publish the address record") && msg.contains("404"),
        "unexpected error: {msg}"
    );
    assert!(lookup.rejected() >= 1, "the gate saw the rejected publish");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_client_never_publishes() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let (_relay, relay_url) = spawn_relay().await?;
    let secret = LookupSecret::generate();
    let lookup = GatedPkarr::spawn(&secret).await?;
    let relay_config = RelayConfig::resolve(settings(&relay_url, &lookup.url, &secret))?;
    let client = create_endpoint(
        &relay_config,
        endpoint_builder(&relay_config, options(false)),
        false,
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        lookup.record(&client.id()).is_none(),
        "an endpoint that only dials out must not publish itself"
    );
    client.close().await;
    Ok(())
}
