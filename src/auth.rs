//! Endpoint-bound public-key authentication over the shared
//! [`flexaccess_keys`] format.
//!
//! Key management lives in
//! [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys): the
//! `ed25519-sec:` / `ed25519-pub:` token format, key files, authorized-keys
//! parsing, and the `generate-auth-key` / `show-auth-key` CLI. Reading key
//! files is the application's job (with `flexaccess_keys::load_private_key`
//! and `flexaccess_keys::load_authorized_keys`); this module owns only the one
//! transcript every FlexAccess program uses to prove a keypair over an iroh
//! connection, and the application supplies its domain-separation context.
//!
//! ## Transcript
//! The client's iroh endpoint id stays ephemeral. In its handshake the client
//! sends its public key, its claimed endpoint id, and an ed25519 signature
//! over that endpoint id, domain-separated by the application's context (for
//! example `b"flextunnel-client-auth-v1"`). The server checks that the claimed
//! id equals the connection's TLS-authenticated `remote_id()`, that the
//! signature verifies under the presented public key
//! ([`verify_endpoint_id_signature`]), and that the key is on its
//! authorized-keys file — binding the credential to this connection so a
//! captured handshake cannot be replayed from another endpoint. The context
//! guarantees a signature made for one application can never satisfy another
//! that shares the key format.

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use flexaccess_keys::{PrivateKey, PublicKey};
use iroh::EndpointId;

pub use flexaccess_keys::AuthorizedKeys;

/// A client authentication keypair: a shared-format [`PrivateKey`] that signs
/// the endpoint-binding transcript.
#[derive(Clone)]
pub struct ClientKey {
    private: PrivateKey,
}

/// `Debug` shows only the public half — the secret must never leak into
/// logs or error context.
impl std::fmt::Debug for ClientKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKey")
            .field("public", &self.public_str())
            .finish_non_exhaustive()
    }
}

impl From<PrivateKey> for ClientKey {
    fn from(private: PrivateKey) -> Self {
        Self { private }
    }
}

impl ClientKey {
    /// Generate a fresh random keypair. Fails only when the system RNG is
    /// unavailable — fallible rather than panicking because FFI surfaces call
    /// this, and a panic there aborts the host app process.
    pub fn generate() -> Result<Self> {
        let private = PrivateKey::generate()
            .map_err(anyhow::Error::from)
            .context("Failed to generate an authentication keypair")?;
        Ok(private.into())
    }

    /// Parse an encoded secret key (`ed25519-sec:...`).
    pub fn from_secret_str(s: &str) -> Result<Self> {
        let private = s
            .parse::<PrivateKey>()
            .map_err(anyhow::Error::from)
            .context("Invalid authentication private key")?;
        Ok(private.into())
    }

    /// The encoded secret key (`ed25519-sec:...`).
    pub fn secret_str(&self) -> String {
        self.private.to_token()
    }

    /// The encoded public key (`ed25519-pub:...`).
    pub fn public_str(&self) -> String {
        self.private.public_key().to_token()
    }

    /// The verifying half of this keypair.
    pub fn public_key(&self) -> PublicKey {
        self.private.public_key()
    }

    /// Sign the client-auth message binding `endpoint_id` (this client's own
    /// ephemeral iroh id) under the application's domain-separation `context`,
    /// returning the base64url signature.
    pub fn sign_endpoint_id(&self, context: &[u8], endpoint_id: &EndpointId) -> String {
        let sig = self.private.sign(&auth_message(context, endpoint_id));
        URL_SAFE_NO_PAD.encode(sig)
    }
}

/// The signed message: domain-separation context + the raw endpoint-id bytes.
fn auth_message(context: &[u8], endpoint_id: &EndpointId) -> Vec<u8> {
    let mut msg = Vec::with_capacity(context.len() + 32);
    msg.extend_from_slice(context);
    msg.extend_from_slice(endpoint_id.as_bytes());
    msg
}

/// Verify a base64url client-auth signature over `endpoint_id` under `public`
/// and the application's domain-separation `context`. Malformed input is
/// simply `false`.
pub fn verify_endpoint_id_signature(
    public: &PublicKey,
    context: &[u8],
    endpoint_id: &EndpointId,
    signature_b64: &str,
) -> bool {
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(signature_b64) else {
        return false;
    };
    public.verify(&auth_message(context, endpoint_id), &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flexaccess_keys::{PRIVATE_KEY_PREFIX, PUBLIC_KEY_PREFIX};
    use iroh::SecretKey;

    const CONTEXT: &[u8] = b"test-client-auth-v1";

    fn ephemeral_endpoint_id() -> EndpointId {
        SecretKey::generate().public()
    }

    #[test]
    fn keypair_roundtrip() {
        let key = ClientKey::generate().unwrap();
        let secret = key.secret_str();
        assert!(secret.starts_with(PRIVATE_KEY_PREFIX));
        let public = key.public_str();
        assert!(public.starts_with(PUBLIC_KEY_PREFIX));

        let reparsed = ClientKey::from_secret_str(&secret).unwrap();
        assert_eq!(reparsed.public_str(), public);
        assert_eq!(public.parse::<PublicKey>().unwrap(), key.public_key());
    }

    #[test]
    fn debug_hides_the_secret() {
        let key = ClientKey::generate().unwrap();
        let shown = format!("{key:?}");
        assert!(shown.contains(&key.public_str()));
        assert!(!shown.contains(&key.secret_str()));
    }

    #[test]
    fn secret_str_rejects_bad_inputs() {
        // Wrong prefix (a public key is not a secret key).
        let key = ClientKey::generate().unwrap();
        assert!(ClientKey::from_secret_str(&key.public_str()).is_err());
        // Bad base64.
        assert!(ClientKey::from_secret_str("ed25519-sec:!!!").is_err());
        // Wrong length.
        let short = format!("{}{}", PRIVATE_KEY_PREFIX, URL_SAFE_NO_PAD.encode([0u8; 16]));
        assert!(ClientKey::from_secret_str(&short).is_err());
    }

    #[test]
    fn signature_binds_endpoint_id_and_context() {
        let key = ClientKey::generate().unwrap();
        let id = ephemeral_endpoint_id();
        let sig = key.sign_endpoint_id(CONTEXT, &id);
        assert!(verify_endpoint_id_signature(&key.public_key(), CONTEXT, &id, &sig));

        // A different endpoint id (replay from another endpoint) fails.
        let other_id = ephemeral_endpoint_id();
        assert!(!verify_endpoint_id_signature(&key.public_key(), CONTEXT, &other_id, &sig));

        // A different key fails.
        let other_key = ClientKey::generate().unwrap();
        assert!(!verify_endpoint_id_signature(&other_key.public_key(), CONTEXT, &id, &sig));

        // A different application's context fails: the same key, id, and
        // signature never carry over between programs sharing the key format.
        assert!(!verify_endpoint_id_signature(
            &key.public_key(),
            b"other-app-client-auth-v1",
            &id,
            &sig
        ));

        // Garbage signatures fail instead of erroring.
        assert!(!verify_endpoint_id_signature(&key.public_key(), CONTEXT, &id, "!!!"));
        assert!(!verify_endpoint_id_signature(&key.public_key(), CONTEXT, &id, ""));
    }

}
