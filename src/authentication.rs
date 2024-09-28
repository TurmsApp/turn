//! Handle authentification logic.

use libturms::error::Error as TurmsError;
use libturms::jwt::*;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use turn::auth::*;
use turn::Error;

pub fn string_to_algorithm(algo: String) -> Algorithm {
    match algo.to_uppercase().as_str() {
        "ES256" => Algorithm::ES256,
        "ES384" => Algorithm::ES384,
        "EDDSA" => Algorithm::EdDSA,
        "HS256" => Algorithm::HS256,
        "HS384" => Algorithm::HS384,
        "HS512" => Algorithm::HS512,
        "PS256" => Algorithm::PS256,
        "PS384" => Algorithm::PS384,
        "PS512" => Algorithm::PS512,
        "RS256" => Algorithm::RS256,
        "RS384" => Algorithm::RS384,
        "RS512" => Algorithm::RS512,
        _ => Algorithm::RS256,
    }
}

/// Authentication management.
/// Checks connection information.
#[derive(Default)]
pub struct Authenticator {
    /// Username and password combo.
    pub combo: HashMap<String, Vec<u8>>, // fight!
    token_manager: Option<TokenManager>,
    /// Allow only specified IPs to connect.
    /// Leave empty to allow all IPs.
    allowed_ips: Vec<SocketAddr>,
}

impl Authenticator {
    /// Allow usage of jsonwebtoken to connect.
    pub fn public_key<P: AsRef<Path>>(
        &mut self,
        key: Key<P>,
    ) -> Result<(), TurmsError> {
        self.token_manager = Some(TokenManager::new(None, key)?);
        Ok(())
    }

    /// Update algorithm used by JWT.
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        if let Some(manager) = self.token_manager {
            self.token_manager = Some(manager.algorithm(algorithm));
        }
        self
    }

    /// Insert a new combo user-password.
    pub fn add_user(
        &mut self,
        username: String,
        password: String,
        realm: &str,
    ) {
        let key = generate_auth_key(&username, realm, &password);
        self.combo.insert(username, key);
    }
}

impl AuthHandler for Authenticator {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        src_addr: SocketAddr,
    ) -> Result<Vec<u8>, Error> {
        // Check user IP.
        if !self.allowed_ips.is_empty()
            && self.allowed_ips.iter().any(|ip| ip.ip() != src_addr.ip())
        {
            return Err(Error::ErrPeerAddressFamilyMismatch);
        }

        if let Some(manager) = &self.token_manager {
            let _claims = manager.decode(username).map_err(|_error| {
                Error::Other("Perhaps your token has expired?".into())
            })?;

            Ok(Vec::new())
        } else if let Some(pw) = self.combo.get(username) {
            Ok(pw.clone())
        } else {
            Err(Error::ErrClosed)
        }
    }
}
