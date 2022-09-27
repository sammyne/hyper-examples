use std::convert::Infallible;

use hyper::server::conn::Http;
use hyper::service::service_fn;
use hyper::{Body, Request, Response};
use tokio::net::TcpListener;

#[tokio::main]
pub async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = "127.0.0.1:3000";
    let listener = TcpListener::bind(addr).await.expect("listen");
    println!("Listening on http://{}", addr);

    loop {
        let (socket, peer_addr) = listener.accept().await?;
        tokio::spawn(async move {
            println!("request from client {peer_addr}");

            let _ = Http::new()
                .serve_connection(socket, service_fn(hello))
                .await;
        });
    }
}

async fn hello(_: Request<Body>) -> Result<Response<Body>, Infallible> {
    Ok(Response::new(Body::from("Hello World!")))
}
