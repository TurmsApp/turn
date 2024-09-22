//! Handle authentification logic.

use std::path::Path;
use std::collections::HashMap;
use std::net::SocketAddr;
use turn::auth::AuthHandler;
use turn::Error;
use libturms::jwt::*;
use libturms::error::Error as TurmsError;

/// Authentication management.
/// Checks connection information.
#[derive(Default)]
pub struct Authenticator {
    /// Username and password combo.
    combo: HashMap<String, Vec<u8>>, // fight!
    token_manager: Option<TokenManager>,
    /// Allow only specified IPs to connect.
    /// Leave empty to allow all IPs.
    allowed_ips: Vec<SocketAddr>,
}

impl Authenticator {
    /// Allow usage of jsonwebtoken to connect.
    pub fn public_key<P: AsRef<Path>>(mut self, key: Key<P>) -> Result<Self, TurmsError> {
        self.token_manager = Some(TokenManager::new(None, key)?);
        Ok(self)
    }

    /// Update algorithm used by JWT.
    pub fn algorithm(mut self, algorithm: Algorithm) -> Self {
        if let Some(manager) = self.token_manager {
            self.token_manager = Some(manager.algorithm(algorithm));
        }
        self
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
                Error::Other(format!(
                    "Perhaps your token has expired?"
                ))
            })?;

            Ok(Vec::new())
        } else if let Some(pw) = self.combo.get(username) {
            Ok(pw.clone())
        } else {
            Err(Error::ErrClosed)
        }
    }
}
