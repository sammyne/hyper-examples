use hyper::{body::to_bytes, client, Body, Method, Request, Uri};
use rustls::client::ServerCertVerified;

use std::io;
use std::str::FromStr;
use std::sync::Arc;

fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let url = Uri::from_str("https://localhost:1337/echo").map_err(|e| error(format!("{}", e)))?;


    let tls_config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(MyServerCertVerifier::new())
        .with_no_client_auth();
        //.with_single_cert(certs, privkey)
        //.expect("build tls config");

    // Prepare the HTTPS connector
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    // Build the hyper client from the HTTPS connector.
    let client: client::Client<_, hyper::Body> = client::Client::builder().build(https);

    let request = Request::builder()
        .method(Method::POST)
        .uri(url)
        .body(Body::from("tkms testbot without cert\n"))
        .expect("build request");
    let reply = client
        .request(request)
        .await
        .map_err(|err| error(format!("do request: {err}")))?;
    let body = to_bytes(reply.into_body())
        .await
        .map_err(|e| error(format!("Could not get body: {:?}", e)))?;
    println!("Body:\n{}", String::from_utf8_lossy(&body));

    Ok(())
}

// by xiangminli
struct MyServerCertVerifier {}

impl MyServerCertVerifier {
    fn new() -> Arc<Self> {
        Arc::new(Self {})
    }
}

impl rustls::client::ServerCertVerifier for MyServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        println!("verifying server's cert ...");
        Ok(ServerCertVerified::assertion())
    }
}
