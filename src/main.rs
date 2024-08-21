//! Implementation of a TURN server with token authentication.
//! TURN servers are used to relay messages between different users.

mod authentication;
mod logger;
mod metrics;

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::Duration;
use tracing::info;
use turn::auth::*;
use turn::relay::relay_static::*;
use turn::server::config::*;
use turn::server::*;
use turn::Error;
use webrtc_util::vnet::net::*;

struct MyAuthHandler {
    cred_map: HashMap<String, Vec<u8>>,
}

impl MyAuthHandler {
    fn new(cred_map: HashMap<String, Vec<u8>>) -> Self {
        MyAuthHandler { cred_map }
    }
}

impl AuthHandler for MyAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error> {
        if let Some(pw) = self.cred_map.get(username) {
            //log::debug!("username={}, password={:?}", username, pw);
            Ok(pw.to_vec())
        } else {
            Err(Error::ErrFakeErr)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Init tracing (as logger).
    logger::init_tracing();
    // Init Prometheus metrics.
    metrics::register_custom_metrics();

    let public_ip = std::env::var("PUBLIC_IP").unwrap_or("0.0.0.0".into());
    let port = std::env::var("PORT").unwrap_or("3478".into());
    let realm = std::env::var("REALM").unwrap_or("".into());

    let creds: Vec<&str> = vec!["user=pass"];
    let mut cred_map = HashMap::new();
    for user in creds {
        let cred: Vec<&str> = user.splitn(2, '=').collect();
        let key = generate_auth_key(cred[0], &realm, cred[1]);
        cred_map.insert(cred[0].into(), key);
    }

    let conn = Arc::new(UdpSocket::bind(format!("0.0.0.0:{port}")).await?);
    info!("Listening to UDP on {}", conn.local_addr()?);

    let server = Server::new(ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                relay_address: IpAddr::from_str(&public_ip)?,
                address: "0.0.0.0".into(),
                net: Arc::new(Net::new(None)),
            }),
        }],
        realm: realm,
        auth_handler: Arc::new(MyAuthHandler::new(cred_map)),
        channel_bind_timeout: Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await?;

    signal::ctrl_c().await.expect("failed to listen for event");
    info!("\nClosing TURN server");
    server.close().await?;

    Ok(())
}
