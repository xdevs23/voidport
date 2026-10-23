//! Every token of this format has the same header, the same process id and a
//! signature of the same length, so the longest one is the token of the largest
//! session id. The signer computes its length once, at startup, and a joining
//! hello that declares a longer token is refused before any of it is read.
//!
//! The token has no expiry: a session ends with its last connection, and a
//! token of an ended session names nothing. The process id in `iss` makes a
//! token name one session of one process even when servers share a key file.
//! The key appears in no log, no session list and no reply.
//!
//! The library makes and checks a token with allocations that abort the process
//! when memory is refused, and no fallible form of them is reachable from here.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey as _, EncodePrivateKey as _};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use voidport_proto::ops::handshake::TOKEN_LEN_MAX;

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    iss: String,
}

#[derive(Serialize)]
struct Minted<'a> {
    sub: Decimal,
    iss: &'a str,
}

struct Decimal(u64);

impl Serialize for Decimal {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.0)
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KeyError {
    #[error("server.signing_key {}: cannot read the key file", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("server.signing_key {}: not an Ed25519 private key in PEM form", path.display())]
    Kind { path: PathBuf },
    #[error("cannot draw a signing key and a server id from the random source")]
    Random {
        #[source]
        source: std::io::Error,
    },
    #[error("cannot encode the generated signing key")]
    Encode,
    #[error("the signing key cannot sign a session token")]
    Sign,
    #[error(
        "a session token of {longest} bytes is longer than the {TOKEN_LEN_MAX} bytes the protocol allows"
    )]
    TokenTooLong { longest: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    Unverified,
    Ended,
}

impl Refused {
    #[must_use]
    pub fn errno(self) -> Errno {
        match self {
            Self::Unverified => Errno::ACCESS,
            Self::Ended => Errno::NOENT,
        }
    }
}

pub struct Signer {
    encoding: EncodingKey,
    decoding: DecodingKey,
    instance: String,
    validation: Validation,
    longest: usize,
}

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Signer")
            .field("instance", &self.instance)
            .finish_non_exhaustive()
    }
}

impl Signer {
    pub fn load(setting: Option<&Path>) -> Result<Self, KeyError> {
        match setting {
            Some(path) => Self::from_file(path),
            None => Self::generated(),
        }
    }

    pub fn from_file(path: &Path) -> Result<Self, KeyError> {
        let pem = std::fs::read(path).map_err(|source| KeyError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let kind = || KeyError::Kind {
            path: path.to_path_buf(),
        };
        let encoding = EncodingKey::from_ed_pem(&pem).map_err(|_| kind())?;
        // The library takes any PKCS#8 document labelled as an Ed key; parsing
        // it as an Ed25519 key is what rejects another curve at startup
        // instead of at the first session.
        let key = SigningKey::from_pkcs8_der(encoding.as_bytes()).map_err(|_| kind())?;
        Self::with(encoding, &key)
    }

    pub fn generated() -> Result<Self, KeyError> {
        let key = SigningKey::from_bytes(&random::<32>()?);
        let der = key.to_pkcs8_der().map_err(|_| KeyError::Encode)?;
        Self::with(EncodingKey::from_ed_der(der.as_bytes()), &key)
    }

    fn with(encoding: EncodingKey, key: &SigningKey) -> Result<Self, KeyError> {
        let instance = uuid::Builder::from_random_bytes(random::<16>()?)
            .into_uuid()
            .to_string();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims = HashSet::from(["sub".to_owned(), "iss".to_owned()]);
        validation.validate_exp = false;
        let mut signer = Self {
            encoding,
            decoding: DecodingKey::from_ed_der(key.verifying_key().as_bytes()),
            instance,
            validation,
            longest: 0,
        };
        signer.longest = allowed(signer.mint(u64::MAX).map_err(|_| KeyError::Sign)?.len())?;
        Ok(signer)
    }

    #[must_use]
    pub fn instance(&self) -> &str {
        &self.instance
    }

    #[must_use]
    pub fn longest(&self) -> usize {
        self.longest
    }

    pub fn mint(&self, session: u64) -> Result<String, Errno> {
        let claims = Minted {
            sub: Decimal(session),
            iss: &self.instance,
        };
        jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &self.encoding).map_err(
            |error| {
                tracing::error!(%error, "a session token could not be signed");
                Errno::IO
            },
        )
    }

    pub fn verify(&self, token: &[u8]) -> Result<u64, Refused> {
        let data = jsonwebtoken::decode::<Claims>(token, &self.decoding, &self.validation)
            .map_err(|_| Refused::Unverified)?;
        let session = data.claims.sub.parse().map_err(|_| Refused::Unverified)?;
        if data.claims.iss != self.instance {
            return Err(Refused::Ended);
        }
        Ok(session)
    }
}

fn random<const N: usize>() -> Result<[u8; N], KeyError> {
    crate::random::bytes().map_err(|source| KeyError::Random { source })
}

fn allowed(longest: usize) -> Result<usize, KeyError> {
    if longest > TOKEN_LEN_MAX {
        return Err(KeyError::TokenTooLong { longest });
    }
    Ok(longest)
}

#[cfg(test)]
mod tests {
    use super::*;

    use voidport_test_host::Scratch;

    fn pem(key: &SigningKey) -> String {
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        key.to_pkcs8_pem(LineEnding::LF)
            .expect("an encodable key")
            .to_string()
    }

    #[test]
    fn a_token_longer_than_the_protocol_allows_is_refused() {
        assert_eq!(allowed(TOKEN_LEN_MAX).ok(), Some(TOKEN_LEN_MAX));
        assert!(matches!(
            allowed(TOKEN_LEN_MAX + 1),
            Err(KeyError::TokenTooLong { longest }) if longest == TOKEN_LEN_MAX + 1
        ));
    }

    #[test]
    fn a_generated_key_mints_tokens_that_verify() {
        let signer = Signer::load(None).expect("a generated key");
        let token = signer.mint(42).expect("signed");
        assert_eq!(signer.verify(token.as_bytes()), Ok(42));
        let other = Signer::generated().expect("a generated key");
        assert_eq!(
            other.verify(token.as_bytes()),
            Err(Refused::Unverified),
            "another key does not verify it"
        );
        assert_ne!(signer.instance(), other.instance());
        assert_eq!(
            uuid::Uuid::parse_str(signer.instance())
                .expect("a UUID")
                .get_version(),
            Some(uuid::Version::Random)
        );
    }

    #[test]
    fn the_longest_token_is_the_one_of_the_largest_session_id() {
        let signer = Signer::generated().expect("a generated key");
        let longest = signer.mint(u64::MAX).expect("signed").len();
        assert_eq!(signer.longest(), longest);
        for session in [1, 42, u64::from(u32::MAX), u64::MAX - 1] {
            assert!(signer.mint(session).expect("signed").len() <= longest);
        }
    }

    #[test]
    fn a_sub_claim_that_is_not_a_session_id_does_not_verify() {
        let signer = Signer::generated().expect("a generated key");
        for iss in [signer.instance().to_owned(), "another process".to_owned()] {
            let claims = Claims {
                sub: "not a number".to_owned(),
                iss,
            };
            let token =
                jsonwebtoken::encode(&Header::new(Algorithm::EdDSA), &claims, &signer.encoding)
                    .expect("signed");
            assert_eq!(signer.verify(token.as_bytes()), Err(Refused::Unverified));
        }
    }

    #[test]
    fn a_token_without_expiry_passes_its_validator() {
        let signer = Signer::generated().expect("a generated key");
        let token = signer.mint(7).expect("signed");
        let claims =
            jsonwebtoken::dangerous::insecure_decode::<serde_json::Value>(token.as_bytes())
                .expect("a token")
                .claims;
        assert_eq!(claims["sub"], "7");
        assert_eq!(claims["iss"], signer.instance());
        assert!(claims.get("exp").is_none(), "no expiry: {claims}");
        assert_eq!(signer.verify(token.as_bytes()), Ok(7));
    }

    #[test]
    fn a_changed_token_or_another_algorithm_does_not_verify() {
        let signer = Signer::generated().expect("a generated key");
        let token = signer.mint(3).expect("signed");
        let mut changed = token.clone().into_bytes();
        let last = changed.len() - 2;
        changed[last] = if changed[last] == b'A' { b'B' } else { b'A' };
        assert_eq!(signer.verify(&changed), Err(Refused::Unverified));

        let claims = Claims {
            sub: "3".to_owned(),
            iss: signer.instance().to_owned(),
        };
        let hmac = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(b"a shared secret"),
        )
        .expect("signed");
        assert_eq!(signer.verify(hmac.as_bytes()), Err(Refused::Unverified));
        assert_eq!(signer.verify(b"not a token"), Err(Refused::Unverified));
        assert_eq!(Refused::Unverified.errno(), Errno::ACCESS);
    }

    #[test]
    fn a_shared_key_verifies_across_processes_and_names_only_its_own() {
        let scratch = Scratch::new("token-shared");
        let key = SigningKey::from_bytes(&random::<32>().expect("random bytes"));
        let path = scratch.file("key.pem", pem(&key).as_bytes());
        let first = Signer::load(Some(&path)).expect("the key loads");
        let second = Signer::from_file(&path).expect("the key loads");
        assert_ne!(first.instance(), second.instance());
        let token = first.mint(5).expect("signed");
        assert_eq!(first.verify(token.as_bytes()), Ok(5));
        assert_eq!(second.verify(token.as_bytes()), Err(Refused::Ended));
        assert_eq!(Refused::Ended.errno(), Errno::NOENT);

        let decoding = DecodingKey::from_ed_der(key.verifying_key().as_bytes());
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims = HashSet::from(["sub".to_owned()]);
        validation.validate_exp = false;
        assert!(jsonwebtoken::decode::<Claims>(token.as_bytes(), &decoding, &validation).is_ok());
    }

    #[test]
    fn a_missing_or_malformed_key_file_is_refused() {
        let scratch = Scratch::new("token-refused");
        let missing = scratch.join("absent.pem");
        let error = Signer::load(Some(&missing)).expect_err("missing");
        assert!(matches!(error, KeyError::Read { .. }), "{error}");
        assert!(error.to_string().contains("server.signing_key"), "{error}");
        assert!(error.to_string().contains("absent.pem"), "{error}");

        let garbage = scratch.file("garbage.pem", b"not a key at all\n");
        let error = Signer::load(Some(&garbage)).expect_err("malformed");
        assert!(matches!(error, KeyError::Kind { .. }), "{error}");
        assert!(error.to_string().contains("garbage.pem"), "{error}");

        let key = SigningKey::from_bytes(&random::<32>().expect("random bytes"));
        use ed25519_dalek::pkcs8::EncodePublicKey as _;
        use ed25519_dalek::pkcs8::spki::der::pem::LineEnding;
        let public = key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("an encodable key");
        let public = scratch.file("public.pem", public.as_bytes());
        let error = Signer::load(Some(&public)).expect_err("the wrong kind");
        assert!(matches!(error, KeyError::Kind { .. }), "{error}");
    }
}
