//! The end-to-end harness for this crate: the smallest program that puts
//! every module through real relays, driven by the scripts in `e2e/`.
//!
//! It is deliberately not an application. A `server` binds an endpoint with
//! the shared builder, runs the shared home-relay failover beside its accept
//! loop, and answers one request per connection: the endpoint-bound auth
//! transcript from [`flexaccess_iroh::auth`] followed by an echo of the
//! client's message. A `client` builds an ephemeral endpoint the same way,
//! dials the server through the configured relays, proves its key, and exits
//! `0` on a clean echo or [`EXIT_AUTH_REJECTED`] when the server refuses the
//! key. Everything an application would add on top — a product ALPN, QUIC
//! tuning, config files, forwarding — is left out so a failure here is a
//! failure of this crate or of iroh, never of a product.
//!
//! The remaining subcommands are the test fixtures the relay-failover suite
//! needs, kept in Rust so the suite depends on nothing but `cargo` and
//! `iroh-relay`: `keygen` writes a client key in the shared format, `fake-relay`
//! is a relay that answers net-report probes but refuses relay connections,
//! `delay-proxy` makes a relay measurably slower, and `pick-port` allocates
//! free localhost ports.

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use flexaccess_iroh::auth::{ClientKey, verify_endpoint_id_signature};
use flexaccess_iroh::endpoint::{EndpointOptions, create_endpoint, endpoint_builder};
use flexaccess_iroh::flexaccess_keys::{self, AuthorizedKeys, PrivateKey, PublicKey};
use flexaccess_iroh::relay::RelayConfig;
use flexaccess_iroh::relay_failover::fail_over_home_relay;
use iroh::endpoint::{Connection, Incoming, QuicTransportConfig};
use iroh::{Endpoint, EndpointAddr, EndpointId, SecretKey, TransportAddr};
use log::{error, info, warn};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The harness's own ALPN; no product speaks it.
const ALPN: &[u8] = b"flexaccess-iroh/e2e/1";

/// The harness's domain-separation context for the auth transcript.
const AUTH_CONTEXT: &[u8] = b"flexaccess-iroh-e2e-client-auth-v1";

/// Client exit status when the server rejects its authentication key.
const EXIT_AUTH_REJECTED: u8 = 3;

/// Upper bound on one request or response; the protocol is two short lines.
const MAX_MESSAGE: usize = 64 * 1024;

/// How long a server waits for a client to close after answering it.
const CLIENT_CLOSE_GRACE: Duration = Duration::from_secs(10);

#[derive(Parser)]
#[command(about = "End-to-end harness for the flexaccess-iroh crate", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bind an endpoint, run the home-relay failover, and answer clients.
    Server(ServerArgs),
    /// Dial a server, prove the client key, and check one echo.
    Client(ClientArgs),
    /// Write a client authentication key in the shared flexaccess-keys format.
    Keygen(KeygenArgs),
    /// A relay that answers net-report probes (`GET /ping`) but refuses
    /// relay connections (404 on everything else).
    FakeRelay {
        /// Port to listen on (127.0.0.1).
        #[arg(long)]
        port: u16,
    },
    /// A TCP proxy that delays every new connection before forwarding it,
    /// so the relay behind it always measures slower in the net report.
    DelayProxy {
        /// Port to listen on (127.0.0.1).
        #[arg(long)]
        listen: u16,
        /// Port to forward to (127.0.0.1).
        #[arg(long)]
        upstream: u16,
        /// Delay added before each new connection is forwarded.
        #[arg(long)]
        delay_ms: u64,
    },
    /// Print free localhost TCP ports, one per line, all distinct.
    PickPort {
        #[arg(long, default_value_t = 1)]
        count: usize,
    },
}

/// The relay choice shared by `server` and `client`, mapped straight onto
/// [`RelayConfig`] and [`EndpointOptions`].
#[derive(Args)]
struct RelayArgs {
    /// Custom relay URL (repeatable; at least two distinct, or none for the
    /// default relays). Custom relays disable n0 internet discovery.
    #[arg(long = "relay-url")]
    relay_urls: Vec<String>,
    /// Shared relay auth token, sent to every custom relay.
    #[arg(long, env = "E2E_RELAY_AUTH_TOKEN")]
    relay_auth_token: Option<String>,
    /// Reach peers only through the configured relays: no direct paths, no
    /// address lookup of any kind. Requires custom relays.
    #[arg(long)]
    relay_only: bool,
}

impl RelayArgs {
    fn resolve(&self) -> Result<RelayConfig> {
        let config = RelayConfig::from_urls_with_token(&self.relay_urls, self.relay_auth_token.clone())?;
        if self.relay_only && !config.is_custom() {
            bail!("--relay-only requires custom relays (--relay-url, at least two)");
        }
        Ok(config)
    }

    fn options(&self, publish_address: bool) -> EndpointOptions {
        EndpointOptions {
            transport_config: QuicTransportConfig::default(),
            publish_address,
            relay_only: self.relay_only,
        }
    }
}

#[derive(Args)]
struct ServerArgs {
    #[command(flatten)]
    relay: RelayArgs,
    /// Authorized-keys file (flexaccess-keys format).
    #[arg(long)]
    authorized_keys: PathBuf,
    /// The server identity as a base64 32-byte iroh secret key. A fresh
    /// identity is generated when absent; either way the EndpointId is logged.
    #[arg(long, env = "E2E_SERVER_SECRET", hide_env_values = true)]
    secret: Option<String>,
}

#[derive(Args)]
struct ClientArgs {
    #[command(flatten)]
    relay: RelayArgs,
    /// The server's EndpointId, as logged by `server`.
    #[arg(long)]
    server_id: EndpointId,
    /// Client authentication key file (flexaccess-keys format).
    #[arg(long)]
    private_key_file: PathBuf,
    /// Payload the server must echo back (a single line).
    #[arg(long, default_value = "hello")]
    message: String,
    /// Seconds to wait for the connection to the server.
    #[arg(long, default_value_t = 30)]
    connect_timeout: u64,
}

#[derive(Args)]
struct KeygenArgs {
    /// Authorized-key comment naming the client.
    comment: String,
    /// Where to write the private key file (created with mode 0600).
    #[arg(long)]
    private_key_file: PathBuf,
    /// Append the key's authorized-keys entry to this file.
    #[arg(long)]
    authorized_keys: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    // The scripts assert on this crate's and the harness's own lines; iroh's
    // tracing (bridged into `log`, spans included) is opt-in via RUST_LOG.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,iroh=warn,iroh_relay=warn,tracing=off"),
    )
    .init();
    let cli = Cli::parse();
    match run(cli.command).await {
        Ok(code) => code,
        Err(e) => {
            error!("{e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(command: Command) -> Result<ExitCode> {
    match command {
        Command::Server(args) => run_server(args).await.map(|()| ExitCode::SUCCESS),
        Command::Client(args) => run_client(args).await,
        Command::Keygen(args) => keygen(args).map(|()| ExitCode::SUCCESS),
        Command::FakeRelay { port } => fake_relay(port).await.map(|()| ExitCode::SUCCESS),
        Command::DelayProxy {
            listen,
            upstream,
            delay_ms,
        } => delay_proxy(listen, upstream, Duration::from_millis(delay_ms))
            .await
            .map(|()| ExitCode::SUCCESS),
        Command::PickPort { count } => pick_ports(count).map(|()| ExitCode::SUCCESS),
    }
}

// ---------------------------------------------------------------------------
// server
// ---------------------------------------------------------------------------

async fn run_server(args: ServerArgs) -> Result<()> {
    let authorized = flexaccess_keys::load_authorized_keys(&args.authorized_keys)
        .map_err(anyhow::Error::from)?;
    if authorized.is_empty() {
        warn!("{} holds no keys; every client will be rejected", args.authorized_keys.display());
    }
    let relay_config = args.relay.resolve()?;
    let secret = match &args.secret {
        Some(secret) => parse_secret(secret)?,
        None => SecretKey::generate(),
    };
    info!("EndpointId: {}", secret.public());

    let builder = endpoint_builder(&relay_config, args.relay.options(true))
        .alpns(vec![ALPN.to_vec()])
        .secret_key(secret);
    let endpoint = create_endpoint(&relay_config, builder).await?;
    info!("Waiting for clients to connect");

    let authorized = Arc::new(authorized);
    let outcome = tokio::select! {
        outcome = accept_loop(&endpoint, &authorized) => outcome,
        () = fail_over_home_relay(&endpoint, &relay_config) => Ok(()),
    };
    endpoint.close().await;
    outcome
}

/// A base64 32-byte secret key. Any 32 bytes are a valid Ed25519 seed, so a
/// script can mint one with `head -c 32 /dev/urandom | base64`.
fn parse_secret(encoded: &str) -> Result<SecretKey> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .context("--secret is not valid base64")?;
    SecretKey::try_from(&bytes[..]).context("--secret must decode to 32 bytes")
}

async fn accept_loop(endpoint: &Endpoint, authorized: &Arc<AuthorizedKeys>) -> Result<()> {
    while let Some(incoming) = endpoint.accept().await {
        let authorized = Arc::clone(authorized);
        tokio::spawn(async move {
            if let Err(e) = serve(incoming, &authorized).await {
                warn!("Connection failed: {e:#}");
            }
        });
    }
    bail!("the endpoint stopped accepting connections")
}

/// One request per connection: the auth line, then the message to echo.
async fn serve(incoming: Incoming, authorized: &AuthorizedKeys) -> Result<()> {
    let conn: Connection = incoming.await.context("accepting connection")?;
    let remote = conn.remote_id();
    let (mut send, mut recv) = conn.accept_bi().await.context("accepting stream")?;
    let request = recv
        .read_to_end(MAX_MESSAGE)
        .await
        .context("reading request")?;
    let request = String::from_utf8(request).context("request is not UTF-8")?;
    let mut lines = request.lines();
    let auth_line = lines.next().context("request without an auth line")?;
    let message = lines.next().unwrap_or_default();

    let response = match authenticate(auth_line, &remote, authorized) {
        Ok(comment) => {
            info!("Client {remote} authenticated successfully as {comment}");
            format!("OK {comment}\n{message}\n")
        }
        Err(reason) => {
            // The client learns only that its proof failed, never which check.
            warn!("Rejected client {remote}: {reason}");
            "REJECTED Invalid authentication proof\n".to_string()
        }
    };
    send.write_all(response.as_bytes())
        .await
        .context("writing response")?;
    send.finish().context("finishing response")?;
    // The client closes once it has read the response; give it a moment so
    // the response is not lost to an early close from this side.
    let _ = tokio::time::timeout(CLIENT_CLOSE_GRACE, conn.closed()).await;
    Ok(())
}

/// Check `<public-key> <endpoint-id> <signature>` against the connection's
/// TLS-authenticated remote id and the authorized keys. `Ok` is the key's
/// comment; `Err` says why it was refused.
fn authenticate(
    line: &str,
    remote: &EndpointId,
    authorized: &AuthorizedKeys,
) -> std::result::Result<String, String> {
    let mut fields = line.split_whitespace();
    let (Some(public), Some(claimed), Some(signature), None) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return Err("malformed auth line".into());
    };
    let public: PublicKey = public
        .parse()
        .map_err(|e| format!("invalid public key: {e}"))?;
    let claimed: EndpointId = claimed
        .parse()
        .map_err(|e| format!("invalid endpoint id: {e}"))?;
    if claimed != *remote {
        return Err(format!("claimed endpoint id {claimed} is not the connection's {remote}"));
    }
    if !verify_endpoint_id_signature(&public, AUTH_CONTEXT, remote, signature) {
        return Err(format!("invalid signature for {public}"));
    }
    match authorized.comment(&public) {
        Some(comment) => Ok(comment.to_string()),
        None => Err(format!("key {public} is not authorized")),
    }
}

// ---------------------------------------------------------------------------
// client
// ---------------------------------------------------------------------------

async fn run_client(args: ClientArgs) -> Result<ExitCode> {
    if args.message.contains(['\n', '\r']) {
        bail!("--message must be a single line");
    }
    let key: ClientKey = flexaccess_keys::load_private_key(&args.private_key_file)
        .map_err(anyhow::Error::from)?
        .into();
    let relay_config = args.relay.resolve()?;
    let builder = endpoint_builder(&relay_config, args.relay.options(false));
    let endpoint = create_endpoint(&relay_config, builder).await?;
    let outcome = exchange(&endpoint, &args, &relay_config, &key).await;
    endpoint.close().await;
    outcome
}

async fn exchange(
    endpoint: &Endpoint,
    args: &ClientArgs,
    relay_config: &RelayConfig,
    key: &ClientKey,
) -> Result<ExitCode> {
    // With custom relays discovery is off, so the relay hints are how the
    // server is reached at all: iroh sends the handshake through every one of
    // them and it succeeds via whichever relay the server is homed on.
    let mut addr = EndpointAddr::new(args.server_id);
    for url in relay_config.custom_urls() {
        addr = addr.with_relay_url(url.clone());
    }
    let timeout = Duration::from_secs(args.connect_timeout);
    info!(
        "Connecting to {} with {} relay hint(s) (timeout {}s)...",
        args.server_id,
        relay_config.custom_urls().len(),
        timeout.as_secs()
    );
    let conn = tokio::time::timeout(timeout, endpoint.connect(addr, ALPN))
        .await
        .map_err(|_| anyhow::anyhow!("connection to {} timed out after {}s", args.server_id, timeout.as_secs()))?
        .context("connecting to the server")?;
    info!("Connected to {} via {}", args.server_id, describe_paths(&conn));

    let id = endpoint.id();
    let signature = key.sign_endpoint_id(AUTH_CONTEXT, &id);
    let request = format!("{} {id} {signature}\n{}\n", key.public_str(), args.message);
    let (mut send, mut recv) = conn.open_bi().await.context("opening stream")?;
    send.write_all(request.as_bytes())
        .await
        .context("sending request")?;
    send.finish().context("finishing request")?;
    let response = recv
        .read_to_end(MAX_MESSAGE)
        .await
        .context("reading response")?;
    conn.close(0u32.into(), b"done");
    let response = String::from_utf8(response).context("response is not UTF-8")?;

    let mut lines = response.lines();
    let status = lines.next().context("empty response")?;
    if let Some(reason) = status.strip_prefix("REJECTED ") {
        error!("Authentication rejected: {reason}");
        return Ok(ExitCode::from(EXIT_AUTH_REJECTED));
    }
    let comment = status
        .strip_prefix("OK ")
        .with_context(|| format!("unexpected response status: {status:?}"))?;
    info!("Authenticated as {comment}");
    let echoed = lines.next().unwrap_or_default();
    if echoed != args.message {
        bail!("echo mismatch: sent {:?}, got {echoed:?}", args.message);
    }
    info!("Echo OK ({} bytes)", args.message.len());
    Ok(ExitCode::SUCCESS)
}

/// The selected paths of a connection, e.g. `Relay http://127.0.0.1:3340/`
/// or `Direct 127.0.0.1:41234`.
fn describe_paths(conn: &Connection) -> String {
    let paths = conn.paths();
    let selected: Vec<String> = paths
        .iter()
        .filter(|path| path.is_selected())
        .map(|path| match path.remote_addr() {
            TransportAddr::Relay(url) => format!("Relay {url}"),
            TransportAddr::Ip(addr) => format!("Direct {addr}"),
            other => format!("{other:?}"),
        })
        .collect();
    if selected.is_empty() {
        "no selected path yet".to_string()
    } else {
        selected.join(", ")
    }
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

fn keygen(args: KeygenArgs) -> Result<()> {
    let key = PrivateKey::generate().map_err(anyhow::Error::from)?;
    let key_file = key
        .to_key_file(&args.comment, SystemTime::now())
        .map_err(anyhow::Error::from)?;
    flexaccess_keys::write_private_key_file(&args.private_key_file, &key_file, false)
        .map_err(anyhow::Error::from)?;
    let entry = key
        .authorized_key(&args.comment)
        .map_err(anyhow::Error::from)?;
    if let Some(path) = &args.authorized_keys {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("opening {}", path.display()))?;
        use std::io::Write;
        writeln!(file, "{entry}")?;
    }
    println!("{entry}");
    Ok(())
}

async fn fake_relay(port: u16) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .with_context(|| format!("binding 127.0.0.1:{port}"))?;
    println!("READY fake relay on 127.0.0.1:{port}");
    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            let _ = serve_fake_relay(stream).await;
        });
    }
}

/// Minimal HTTP/1.1: `GET /ping` gets a 200, anything else (in particular
/// the `/relay` WebSocket upgrade) a 404. Keep-alive, no request bodies.
async fn serve_fake_relay(mut stream: TcpStream) -> Result<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head: Vec<u8> = buf.drain(..end + 4).collect();
            let request_line = head.split(|&b| b == b'\r').next().unwrap_or_default();
            let response: &[u8] = if request_line.starts_with(b"GET /ping ") {
                b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\n\r\npong"
            } else {
                b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
            };
            stream.write_all(response).await?;
        }
    }
}

async fn delay_proxy(listen: u16, upstream: u16, delay: Duration) -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", listen))
        .await
        .with_context(|| format!("binding 127.0.0.1:{listen}"))?;
    println!(
        "READY delay proxy 127.0.0.1:{listen} -> 127.0.0.1:{upstream} (+{}ms)",
        delay.as_millis()
    );
    loop {
        let (mut client, _) = listener.accept().await?;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            // Established connections are forwarded byte for byte: the relay
            // behind the proxy works normally, it is just never the fastest.
            if let Ok(mut server) = TcpStream::connect(("127.0.0.1", upstream)).await {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
            }
        });
    }
}

/// Hold every port bound until all are chosen so they are distinct.
fn pick_ports(count: usize) -> Result<()> {
    let listeners: Vec<std::net::TcpListener> = (0..count)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<_>>()
        .context("binding an ephemeral port")?;
    for listener in &listeners {
        println!("{}", listener.local_addr()?.port());
    }
    Ok(())
}
