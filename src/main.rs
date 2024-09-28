//! Implementation of a TURN server with token authentication.
//! TURN servers are used to relay messages between different users.

mod authentication;
mod logger;
mod metrics;

use authentication::string_to_algorithm;
use authentication::Authenticator;
use libturms::jwt::Key;
use std::env;
use std::fs;
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::signal;
use tokio::time::Duration;
use tracing::*;
use turn::relay::relay_static::*;
use turn::server::config::*;
use turn::server::*;
use turn::Error;
use webrtc_util::vnet::net::*;

#[tokio::main]
async fn main() -> Result<(), Error> {
    // Init tracing (as logger).
    logger::init_tracing();
    // Init Prometheus metrics.
    metrics::register_custom_metrics();

    let public_ip = env::var("PUBLIC_IP").unwrap_or("0.0.0.0".into());
    let port = env::var("PORT").unwrap_or("3478".into());
    let realm = env::var("REALM").unwrap_or("".into());

    let mut authentificator = Authenticator::default().algorithm(
        string_to_algorithm(env::var("JWT_ALGORITHM").unwrap_or_default()),
    );

    if let Ok(path) = env::var("USERS_PATH") {
        match fs::read_to_string(&path) {
            Ok(lines) => {
                for line in lines.lines() {
                    let line = line.to_string().clone();
                    let cred: Vec<&str> = line.splitn(2, '=').collect();

                    debug!(username = cred[0], "Added user.");
                    authentificator.add_user(
                        cred[0].to_owned(),
                        cred[1].to_owned(),
                        &realm,
                    );
                }
            },
            Err(_) => error!(path = path, "Cannot find file."),
        }
    }

    if let Ok(key) = env::var("JWT_PUBLIC_KEY") {
        // If user directly entered public key.
        if key.starts_with("-----BEGIN PUBLIC KEY-----") {
            if authentificator
                .public_key(Key::<String>::Text(key))
                .is_err()
            {
                error!(
                    "JWT key is not valid; make sure you used the public key."
                )
            }
        } else {
            // However, it MUST be a path.
            if authentificator.public_key(Key::Path(key)).is_err() {
                error!("JWT key is not valid: is the path valid? is it the public key?")
            }
        }
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
        realm,
        auth_handler: Arc::new(authentificator),
        channel_bind_timeout: Duration::from_secs(0),
        alloc_close_notify: None,
    })
    .await?;

    signal::ctrl_c().await.expect("failed to listen for event");
    info!("\nClosing TURN server");
    server.close().await?;

    Ok(())
}
