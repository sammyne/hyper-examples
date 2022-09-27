use core::task::{Context, Poll};

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::{io, sync};

use futures_util::ready;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use tokio_rustls::rustls::server::{ClientCertVerified, ClientCertVerifier};
use tokio_rustls::rustls::{Certificate, ServerConfig};

use hello_world::error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:1337".parse()?;

    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs = hello_world::load_certs("static/pki/server.crt")?;
        // Load private key.
        let key = hello_world::load_private_key("static/pki/server.key")?;
        // Do not use client certificate authentication.
        let mut cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_client_cert_verifier(MyClientCertVerifier::new())
            .with_single_cert(certs, key)
            .map_err(|e| error(format!("{}", e)))?;
        // Configure ALPN to accept HTTP/2, HTTP/1.1 in that order.
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        sync::Arc::new(cfg)
    };

    // Create a TCP listener via tokio.
    let incoming = AddrIncoming::bind(&addr)?;
    // ref: https://docs.rs/hyper/0.14.20/hyper/server/index.html#examples
    let service = make_service_fn(|conn: &TlsStream| {
        let peer_certs = conn.peer_certs.clone();

        async move { Ok::<_, io::Error>(service_fn(move |req| hello(peer_certs.clone(), req))) }
    });
    let server = Server::builder(TlsAcceptor::new(tls_cfg, incoming)).serve(service);

    // Run the future, keep going until an error occurs.
    println!("Starting to serve on https://{}.", addr);
    server.await?;
    Ok(())
}

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub struct TlsStream {
    state: State,
    peer_certs: Arc<RwLock<Vec<Certificate>>>, // sync lock is safe
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let accept = tokio_rustls::TlsAcceptor::from(config).accept(stream);

        TlsStream {
            state: State::Handshaking(accept),
            peer_certs: Arc::new(RwLock::new(vec![])),
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut ReadBuf,
    ) -> Poll<io::Result<()>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_read(cx, buf);

                    let (_, conn) = stream.get_ref();
                    let mut v = pin.peer_certs.write().expect("get peer certs lock");
                    *v = conn
                        .peer_certificates()
                        .map(|v| v.to_vec())
                        .unwrap_or_else(|| vec![]);

                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => Poll::Ready(Err(err)),
            },
            State::Streaming(ref mut stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub fn new(config: Arc<ServerConfig>, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor { config, incoming }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

// Custom echo service, handling two different routes and a
// catch-all 404 responder.
async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}

async fn hello(
    peer_certs_lock: Arc<RwLock<Vec<Certificate>>>,
    req: Request<Body>,
) -> Result<Response<Body>, hyper::Error> {
    let peer_certs = {
        let v = peer_certs_lock.read().expect("get peer certs lock");
        v.clone()
    };
    println!("#(peer certs) = {}", peer_certs.len());
    for (i, v) in peer_certs.iter().enumerate() {
        println!("certs[{i}] goes as\n{}", pem_encode_cert(&v.0));
    }

    echo(req).await
}

struct MyClientCertVerifier;

impl MyClientCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ClientCertVerifier for MyClientCertVerifier {
    fn client_auth_mandatory(&self) -> Option<bool> {
        Some(false)
    }

    fn client_auth_root_subjects(&self) -> Option<rustls::DistinguishedNames> {
        Some(vec![])
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _now: std::time::SystemTime,
    ) -> Result<rustls::server::ClientCertVerified, rustls::Error> {
        println!("verifying client cert ...");

        Ok(ClientCertVerified::assertion())
    }
}

fn pem_encode_cert(der: &[u8]) -> String {
    let s = base64::encode(der);
    let body = s
        .as_bytes()
        .chunks(64)
        .map(|v| {
            std::str::from_utf8(v)
                .expect("parse chunk as str")
                .to_string()
        })
        .reduce(|out, v| format!("{out}\n{v}"))
        .expect("join cert pem lines");

    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}
