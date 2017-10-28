#![deny(missing_docs)]

//! A simple Elliptic Curve Diffie-Hellman channel-binding handshake
//! protocol based on X25519 and ChaCha20-Poly1305.
//!
//! **nnshake** implements a [channel-binding] handshake protocol for
//! establishing forward-secure sessions between ephemeral clients and
//! servers with a well-known public key. The protocol authenticates the
//! identity of the server based on its public key. When it concludes,
//! both parties share a pair of ephemeral session keys that can be used
//! safely for symmetric encryption.
//!
//! [channel-binding]: https://tools.ietf.org/html/rfc5056
//!
//! **nnshake** uses these cryptographic primitives:
//! 
//! - [X25519] \(RFC 7748) for ECDH key agreement
//! - [ChaCha20-Poly1305] \(RFC 7539) for [AEAD] symmetric encryption
//! - [HKDF] \(RFC 5869) with HMAC-SHA-512 (using fixed-length salt)
//!   for key derivation
//! - [BLAKE2b] for hashing of user-supplied additional data
//! 
//! [X25519]: https://tools.ietf.org/html/rfc7748
//! [ChaCha20-Poly1305]: https://tools.ietf.org/html/rfc7539
//! [AEAD]: https://en.wikipedia.org/wiki/AEAD
//! [HKDF]: https://tools.ietf.org/html/rfc5869
//! [BLAKE2b]: https://blake2.net/
//! 
//! ## Design
//! 
//! The library does not perform any I/O; it just accepts byte slices from
//! the user for input and output. As such, it can easily be embedded in
//! higher-level protocols and network applications.
//!
//! The API is simple and hard to misuse. Each of the main handshake
//! methods can only be called when the handshake is at the appropriate
//! step, and upon success, each transitions the handshake to the next
//! step.
//! 
//! When the handshake finishes, a pair `(upstream, downstream)` of keys
//! is returned. The intent is that `upstream` is used for client→server
//! encryption (encryption by the client and decryption by the server),
//! and that `downstream` is used conversely.
//!
//! ## Basic Usage
//! 
//! ```
//! extern crate nnshake;
//! 
//! // A static keypair can be generated with examples/static-keygen
//! const SERVER_STATIC_PRIVKEY: [u8; 32] = [
//!     228, 172, 49, 122, 10, 86, 15, 63,
//!     30, 82, 44, 209, 15, 142, 38, 144,
//!     20, 110, 164, 245, 17, 109, 59, 27,
//!     158, 22, 80, 64, 178, 92, 10, 138,
//! ];
//! const SERVER_STATIC_PUBKEY: [u8; 32] = [
//!     85, 215, 107, 196, 200, 26, 154, 112,
//!     186, 205, 170, 96, 156, 87, 242, 31,
//!     134, 36, 10, 205, 133, 18, 230, 211,
//!     38, 179, 240, 57, 75, 251, 43, 122,
//! ];
//! 
//! fn main() {
//!     use nnshake::{Random, Client, Server};
//!     let rng = Random::new();
//! 
//!     // Message 1: Client generates key and sends pubkey to server
//!     let mut c = Client::new(&rng).expect("Client keygen failed");
//! 
//!     // Message 2: Server receives client pubkey, generates key and
//!     // sends pubkey to client
//!     let mut s = Server::new(&rng).expect("Server keygen failed");
//! 
//!     // Both parties compute ECDH key exchange to derive a shared session key
//!     s.kx(c.public_key()).expect("S: Key exchange failed");
//!     c.kx(s.public_key()).expect("C: Key exchange failed");
//! 
//!     // Message 3: Client generates a challenge message to authenticate
//!     // server based on its static public key, and sends to server
//!     let mut challenge_frame = [0u8; 96];
//!     c.challenge(&SERVER_STATIC_PUBKEY, &mut challenge_frame)
//!         .expect("C: Challenge generation failed");
//! 
//!     // Message 4: Server receives challenge, generates response, and
//!     // sends to client
//!     let mut response_frame = [0u8; 48];
//!     s.solve_challenge(&SERVER_STATIC_PRIVKEY, &mut challenge_frame,
//!                       &mut response_frame)
//!         .expect("S: Challenge solution failed");
//! 
//!     // Client receives and validates server's response message
//!     c.check_response(&mut response_frame).expect("C: Invalid response");
//! 
//!     // Client and server now share a pair of keys (upstream, downstream)
//!     // that can be used for symmetric AEAD data transfer
//!     let (c_up_key, c_dn_key) = c.finish().expect("C: Finish failed");
//!     let (s_up_key, s_dn_key) = s.finish().expect("S: Finish failed");
//! 
//!     assert_eq!((*c_up_key, *c_dn_key), (*s_up_key, *s_dn_key));
//! }
//! ```
//!
//! ## Additional Data
//! 
//! Support is provided for supplying additional data during the handshake
//! via the `update_ad_tx()` and `update_ad_rx()` methods. These methods
//! should be used at every step to include any transmitted and received
//! cleartext message headers in the respective hash state. This provides
//! security against alteration of the cleartext headers of messages in
//! transit. If such alteration occurs, the tx hash of the sender will
//! fail to match the rx hash of the receiver. Since this hash is passed
//! as *additional data* during symmetric AEAD encryption and decryption,
//! non-matching hashes will cause a handshake failure when attempting to
//! decrypt Message 3 or Message 4.
//! 
 
// `error_chain!` can recurse deeply
#![recursion_limit = "1024"]

#[macro_use]
extern crate error_chain;
extern crate clear_on_drop;
extern crate ring;
extern crate untrusted;
extern crate blake2_rfc as blake2;

mod errors {
    error_chain!{}
}

use errors::*;

use ring::agreement::EphemeralPrivateKey;
use ring::rand::SecureRandom;
use clear_on_drop::ClearOnDrop;
use blake2::blake2b::Blake2b;

// Fixed AEAD nonces used during the handshake
const CHALLENGE_NONCE: [u8; 12] = [255; 12];
// The next two nonce values MUST be distinct!
const CLIENT_INIT_NONCE: [u8; 12] = [249; 12];
const SERVER_INIT_NONCE: [u8; 12] = [255; 12];

// HKDF `info` (context distinguisher) values
const HKDF_INFO_CHALLENGE_KEY: &[u8] = b"ch-key-0";
const HKDF_INFO_TOKEN: &[u8] = b"btoken-0";
const HKDF_INFO_INIT_KEY: &[u8] = b"init-key";
const HKDF_INFO_SESSION_KEY_UP: &[u8] = b"s-key-up";
const HKDF_INFO_SESSION_KEY_DN: &[u8] = b"s-key-dn";

#[derive(Debug, Default, PartialEq)]
// Wrapper type for secret key values
struct KeyMaterial([u8; 32]);

impl std::ops::Deref for KeyMaterial {
    type Target = [u8; 32];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// A container struct needed to use ClearOnDrop on values
// of type KeyMaterial.
#[derive(Debug, Default)]
/// Cell holding a value that will be cleared on drop.
/// 
/// Implements `Deref` so that its data can be accessed
/// with the `*` operator.
pub struct DropCell<T: std::fmt::Debug + Default>(T);
impl<T> std::ops::Deref for DropCell<T>
    where T: std::fmt::Debug + std::default::Default
{
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<T> std::ops::DerefMut for DropCell<T>
    where T: std::fmt::Debug + std::default::Default
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
// Finally, the thing we'll store our secrets in.
type Secret = ClearOnDrop<DropCell<KeyMaterial>>;

/// Type that session keys are returned as when the handshake
/// finishes.
/// 
/// Implements `Deref` so the key bytes can be accessed
/// with the `*` operator.
pub type SessionKey = ClearOnDrop<DropCell<[u8; 32]>>;

#[derive(Debug)]
// Container that holds the various secrets we derive from the
// ECDH computation.
struct SessionSecrets {
    ee_init_key: Secret,
    ee_token: Secret,
    ee_up_key: Secret,
    ee_dn_key: Secret,
}

#[derive(Clone, Copy, PartialEq)]
// Distinguishes Client from Server handshake instances.
enum Role {
    Client,
    Server,
}
#[derive(PartialEq)]
// Distinguishes the different steps in the handshake.
enum Step {
    One,
    Two,
    Three,
    Four,
}

// Contains the main handshake state data.
struct Handshake<'a> {
    // Reference to system RNG
    rng: &'a SecureRandom,
    // The current step
    step: Step,
    // Temporarily holds the generated ephemeral key
    epk: Option<EphemeralPrivateKey>,
    // Stores the public key corresponding to `epk`
    epk_pubkey: [u8; 32],
    // Transmit-side *additional data* hash state
    ad_hash_tx: Blake2b,
    // Receive-side *additional data* hash state
    ad_hash_rx: Blake2b,
    // Session secrets derived from ECDH computation
    session_keys: Option<SessionSecrets>,
}

/// Instance of the client handshake state machine.
pub struct Client<'a> {
    h: Handshake<'a>,
    // The challenge code that the server needs to provide
    authcode: Option<KeyMaterial>,
}
/// Instance of the server handshake state machine.
pub struct Server<'a> {
    h: Handshake<'a>,
}
/// Operating system random number generator.
pub struct Random;

impl Random {
    /// Returns a new instance of an operating system random number
    /// generator.
    /// 
    /// Only one should be needed per application.
    pub fn new() -> ring::rand::SystemRandom {
        ring::rand::SystemRandom::new()
    }
}

impl<'a> Handshake<'a> {
    fn new(rng: &'a SecureRandom) -> Result<Self> {
        let epk = EphemeralPrivateKey::generate(&ring::agreement::X25519, rng)
            .chain_err(|| "Handshake::new: generate ephemeral key")?;
        let mut pubkey = [0u8; 32];
        epk.compute_public_key(&mut pubkey)
            .chain_err(|| "Handshake::new: compute ephemeral pubkey")?;

        Ok(Handshake {
            step: Step::One,
            rng: rng,
            epk: Some(epk),
            epk_pubkey: pubkey,
            ad_hash_tx: Blake2b::new(32),
            ad_hash_rx: Blake2b::new(32),
            session_keys: None,
        })
    }
    fn update_ad_tx(&mut self, ad: &[u8]) {
        self.ad_hash_tx.update(ad)
    }
    fn update_ad_rx(&mut self, ad: &[u8]) {
        self.ad_hash_rx.update(ad)
    }
    fn kx(&mut self, role: Role, their_pubkey: &[u8; 32]) -> Result<()> {
        use clear_on_drop::clear_stack_on_return;
        ensure!(self.step == Step::One, "kx called in wrong step");

        let keys = clear_stack_on_return(1, || {
            compute_session_secrets(role, self.epk.take().unwrap(), their_pubkey)
        }).chain_err(|| "Handshake::kx")?;
        self.session_keys = Some(keys);

        self.step = Step::Two;
        Ok(())
    }
}
impl<'a> Client<'a> {
    /// Generates an ephemeral ECDH key and returns a new client handshake
    /// instance.
    pub fn new(rng: &'a SecureRandom) -> Result<Self> {
        Ok(Client {
            h: Handshake::new(rng).chain_err(|| "Client::new")?,
            authcode: None,
        })
    }
    /// Returns the bytes of the ephemeral public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.h.epk_pubkey
    }
    /// Updates the transmit-side *additional data* hash with the supplied
    /// data.
    pub fn update_ad_tx(&mut self, ad: &[u8]) {
        self.h.update_ad_tx(ad)
    }
    /// Updates the receive-side *additional data* hash with the supplied
    /// data.
    pub fn update_ad_rx(&mut self, ad: &[u8]) {
        self.h.update_ad_rx(ad)
    }
    /// Performs an ECDH key exchange computation and transitions to the
    /// next step.
    pub fn kx(&mut self, server_ephem_pubkey: &[u8; 32]) -> Result<()> {
        self.h.kx(Role::Client, server_ephem_pubkey)
    }
    /// Generates a challenge message for the server based on the supplied
    /// static public key.
    /// 
    /// The challenge message is 96 bytes and is written to `out`, which must
    /// have sufficient length.
    pub fn challenge(
        &mut self,
        server_static_pubkey: &[u8; 32],
        out: &mut [u8],
    ) -> Result<()> {
        use clear_on_drop::clear_stack_on_return;
        ensure!(self.h.step == Step::Two, "challenge called in wrong step");

        let keys = self.h.session_keys.as_ref().unwrap();
        let (code, challenge) = client_generate_challenge(&keys.ee_token, self.h.rng)
            .chain_err(|| "Client::challenge: generate")?;
        self.authcode = Some(code);

        clear_stack_on_return(1, || {
            client_wrap_challenge(
                server_static_pubkey,
                &*keys.ee_init_key,
                &challenge,
                self.h.ad_hash_tx.clone().finalize().as_bytes(),
                self.h.rng,
                out,
            )
        }).chain_err(|| "Client::challenge: wrap")?;

        self.h.step = Step::Three;
        Ok(())
    }
    /// Validates a 48-byte challenge response message received from the
    /// server.
    ///
    /// This function overwrites the contents of `response_frame`.
    pub fn check_response(&mut self, response_frame: &mut [u8]) -> Result<()> {
        ensure!(
            self.h.step == Step::Three,
            "Client::check_response called in wrong step"
        );
        let init_key = &self.h.session_keys.as_ref().unwrap().ee_init_key;
        let response = client_unwrap_challenge_response(
            init_key,
            response_frame,
            self.h.ad_hash_rx.clone().finalize().as_bytes(),
        ).chain_err(|| "Client::check_response unwrap")?;
        let authcode = self.authcode.as_ref().unwrap();
        if response == **authcode {
            self.h.step = Step::Four;
            Ok(())
        } else {
            Err("Client::check_response: invalid challenge response".into())
        }
    }
    /// After a successful challenge response, this method returns a pair
    /// of 32-byte session keys wrapped in a `DropCell`. The key bytes can
    /// be accessed via the `*` operator.
    pub fn finish(self) -> Result<(SessionKey, SessionKey)> {
        ensure!(
            self.h.step == Step::Four,
            "Client::finish called in wrong step"
        );
        Ok((
            ClearOnDrop::new(DropCell(**self.h.session_keys.as_ref().unwrap().ee_up_key)),
            ClearOnDrop::new(DropCell(**self.h.session_keys.as_ref().unwrap().ee_dn_key)),
        ))
    }
}
impl<'a> Server<'a> {
    /// Generates an ephemeral ECDH key and returns a new server handshake
    /// instance.
    pub fn new(rng: &'a SecureRandom) -> Result<Self> {
        Ok(Server {
            h: Handshake::new(rng).chain_err(|| "Server::new")?,
        })
    }
    /// Returns the bytes of the ephemeral public key.
    pub fn public_key(&self) -> &[u8; 32] {
        &self.h.epk_pubkey
    }
    /// Updates the transmit-side *additional data* hash with the supplied
    /// data.
    pub fn update_ad_tx(&mut self, ad: &[u8]) {
        self.h.update_ad_tx(ad)
    }
    /// Updates the receive-side *additional data* hash with the supplied
    /// data.
    pub fn update_ad_rx(&mut self, ad: &[u8]) {
        self.h.update_ad_rx(ad)
    }
    /// Performs an ECDH key exchange computation and transitions to the
    /// next step.
    pub fn kx(&mut self, client_pubkey: &[u8; 32]) -> Result<()> {
        self.h.kx(Role::Server, client_pubkey)
    }
    /// Processes the supplied 96-byte challenge message from the client
    /// and generates a response message based on the supplied static
    /// private key.
    ///
    /// The response message is 48 bytes and is written to `out`, which must
    /// have sufficient length.
    ///
    /// This function overwrites the contents of `challenge_frame`.
    pub fn solve_challenge(
        &mut self,
        static_privkey_bytes: &[u8; 32],
        challenge_frame: &mut [u8],
        out: &mut [u8],
    ) -> Result<()> {
        use clear_on_drop::clear_stack_on_return;
        ensure!(
            self.h.step == Step::Two,
            "solve_challenge called in wrong step"
        );

        let keys = self.h.session_keys.as_ref().unwrap();
        let solution = clear_stack_on_return(1, || {
            server_unwrap_challenge(
                static_privkey_bytes,
                &keys.ee_init_key,
                &keys.ee_token,
                challenge_frame,
                self.h.ad_hash_rx.clone().finalize().as_bytes(),
            )
        }).chain_err(|| "Server::solve_challenge unwrap")?;
        server_wrap_challenge_response(
            &keys.ee_init_key,
            &solution,
            self.h.ad_hash_tx.clone().finalize().as_bytes(),
            out,
        ).chain_err(|| "Server::solve_challenge respond")?;

        self.h.step = Step::Three;
        Ok(())
    }
    /// After a successful challenge response, this method returns a pair
    /// of 32-byte session keys wrapped in a `DropCell`. The key bytes can
    /// be accessed via the `*` operator.
    pub fn finish(self) -> Result<(SessionKey, SessionKey)> {
        ensure!(
            self.h.step == Step::Three,
            "Server::finish called in wrong step"
        );
        Ok((
            ClearOnDrop::new(DropCell(**self.h.session_keys.as_ref().unwrap().ee_up_key)),
            ClearOnDrop::new(DropCell(**self.h.session_keys.as_ref().unwrap().ee_dn_key)),
        ))
    }
}

// Generates a 32-byte challenge value by XORing a shared token
// with a random value.
fn client_generate_challenge(
    token: &[u8; 32],
    rng: &SecureRandom,
) -> Result<(KeyMaterial, [u8; 32])> {
    let mut code = [0u8; 32];
    rng.fill(&mut code)
        .chain_err(|| "client_generate_challenge: generate code")?;

    let mut challenge = [0u8; 32];
    for i in 0..32 {
        challenge[i] = token[i] ^ code[i];
    }
    Ok((KeyMaterial(code), challenge))
}

// Constructs a challenge message.
fn client_wrap_challenge(
    server_static_pubkey: &[u8; 32],
    ee_init_key: &KeyMaterial,
    challenge: &[u8; 32],
    ad: &[u8],
    rng: &SecureRandom,
    out: &mut [u8],
) -> Result<()> {
    use ring::agreement;
    ensure!(
        out.len() >= 96,
        "client_wrap_challenge: output buffer too small"
    );

    // Generate one-shot challenge key
    let challenge_ephem_key = EphemeralPrivateKey::generate(&agreement::X25519, rng)
        .chain_err(|| "client_wrap_challenge: generate ephemeral key")?;
    challenge_ephem_key
        .compute_public_key(&mut out[..32])
        .chain_err(|| "client_wrap_challenge: compute ephemeral pubkey")?;

    // ECDH(challenge ephem key, server static key) -> symmetric key
    let challenge_sk;
    {
        let raw_sk = ecdh(challenge_ephem_key, server_static_pubkey)
            .chain_err(|| "client_wrap_challenge: ecdh")?;

        // Set up salt = server_static_pubkey || challenge_ephem_pubkey
        let challenge_ephem_pubkey = &out[..32];
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(server_static_pubkey);
        salt[32..].copy_from_slice(challenge_ephem_pubkey);

        // Compute one-shot symmetric key
        let mut sk_buf = [0u8; 32];
        hkdf(&salt, raw_sk, HKDF_INFO_CHALLENGE_KEY, &mut sk_buf);
        challenge_sk = KeyMaterial(sk_buf);
    }

    // Build challenge message
    out[32..64].copy_from_slice(challenge);
    aead_seal(&challenge_sk, &CHALLENGE_NONCE, ad, &mut out[32..80])
        .chain_err(|| "client_wrap_challenge: inner wrap")?;
    aead_seal(ee_init_key, &CLIENT_INIT_NONCE, ad, out)
        .chain_err(|| "client_wrap_challenge: outer wrap")?;
    Ok(())
}

// Unwraps a challenge message constructed by a client and returns
// the solution code.
fn server_unwrap_challenge(
    server_static_privkey_bytes: &[u8; 32],
    ee_init_key: &KeyMaterial,
    ee_token: &KeyMaterial,
    challenge_frame: &mut [u8],
    ad: &[u8],
) -> Result<[u8; 32]> {
    ensure!(
        challenge_frame.len() == 96,
        "server_unwrap_challenge: invalid frame length"
    );

    // Decrypt outer frame -> (client pubkey, inner frame)
    let (challenge_ephem_pubkey, inner_frame);
    {
        let outer_msg = aead_open(&*ee_init_key, &CLIENT_INIT_NONCE, ad, challenge_frame)
            .chain_err(|| "server_unwrap_challenge: outer aead")?;
        let (a, b) = outer_msg.split_at_mut(32);
        challenge_ephem_pubkey = a;
        inner_frame = b;
    }

    // Set up static key
    let (static_privkey, static_pubkey) =
        import_static_key(server_static_privkey_bytes)
        .chain_err(|| "server_unwrap_challenge: import static key")?;

    // ECDH(server static key, challenge ephem pubkey) -> symmetric key
    let challenge_sk;
    {
        let raw_sk = ecdh(static_privkey, challenge_ephem_pubkey)
            .chain_err(|| "server_unwrap_challenge: ecdh")?;

        // Set up salt = server_static_pubkey || challenge_ephem_pubkey
        let mut salt = [0u8; 64];
        salt[..32].copy_from_slice(&static_pubkey);
        salt[32..].copy_from_slice(&challenge_ephem_pubkey);

        // Compute one-shot symmetric key
        let mut sk_buf = [0u8; 32];
        hkdf(&salt, raw_sk, HKDF_INFO_CHALLENGE_KEY, &mut sk_buf);
        challenge_sk = KeyMaterial(sk_buf);
    }

    // Decrypt inner frame -> challenge
    let challenge = aead_open(&challenge_sk, &CHALLENGE_NONCE, ad, inner_frame)
        .chain_err(|| "server_unwrap_challenge: inner aead")?;

    // Solve challenge
    let mut code = [0u8; 32];
    for i in 0..32 {
        code[i] = ee_token[i] ^ challenge[i];
    }
    Ok(code)
}

// Wraps the challenge solution code in a response message to be sent to
// the client.
fn server_wrap_challenge_response(
    ee_init_key: &KeyMaterial,
    solution: &[u8; 32],
    ad: &[u8],
    out: &mut [u8],
) -> Result<()> {
    ensure!(
        out.len() >= 48,
        "server_wrap_challenge_response: output buffer too small"
    );
    out[..32].copy_from_slice(solution);
    aead_seal(ee_init_key, &SERVER_INIT_NONCE, ad, out)
        .chain_err(|| "server_wrap_challenge_response: aead")?;
    Ok(())
}

// Unwraps the solution code from a challenge response message received
// from the server.
fn client_unwrap_challenge_response(
    ee_init_key: &KeyMaterial,
    response_frame: &mut [u8],
    ad: &[u8],
) -> Result<[u8; 32]> {
    ensure!(
        response_frame.len() == 48,
        "client_unwrap_challenge_response: invalid frame length"
    );
    let msg = aead_open(&*ee_init_key, &SERVER_INIT_NONCE, ad, response_frame)
        .chain_err(|| "client_unwrap_challenge_response: aead_open")?;
    let mut output = [0u8; 32];
    output.copy_from_slice(msg);
    Ok(output)
}

// Derives session secrets via ECDH
fn compute_session_secrets(
    role: Role,
    my_ephem_privkey: EphemeralPrivateKey,
    their_ephem_pubkey: &[u8; 32],
) -> Result<SessionSecrets> {
    use ring::hkdf::expand as hkdf_expand;

    let mut my_ephem_pubkey = [0u8; 32];
    my_ephem_privkey
        .compute_public_key(&mut my_ephem_pubkey)
        .chain_err(|| "compute_session_secrets: compute ephemeral pubkey")?;

    // Set HKDF salt = client_ephem_pubkey || server_ephem_pubkey
    let mut salt = [0u8; 64];
    match role {
        Role::Client => {
            salt[..32].copy_from_slice(&my_ephem_pubkey);
            salt[32..].copy_from_slice(their_ephem_pubkey);
        }
        Role::Server => {
            salt[..32].copy_from_slice(their_ephem_pubkey);
            salt[32..].copy_from_slice(&my_ephem_pubkey);
        }
    }

    // ECDH(e, e) -> raw secret -> HKDF extract -> HKDF expansions
    let raw_ee_key =
        ecdh(my_ephem_privkey, their_ephem_pubkey)
        .chain_err(|| "compute_session_secrets: ee ecdh")?;
    let ee_extract = hkdf_extract(&salt, raw_ee_key);

    // Compute binding token
    let mut ee_token = [0u8; 32];
    hkdf_expand(&ee_extract, HKDF_INFO_TOKEN, &mut ee_token);

    // Compute ephemeral-ephemeral init keypair
    let mut ee_init_key = [0u8; 32];
    hkdf_expand(&ee_extract, HKDF_INFO_INIT_KEY, &mut ee_init_key);

    // Compute ephemeral-ephemeral session keypair
    let mut ee_up_key = [0u8; 32];
    hkdf_expand(&ee_extract, HKDF_INFO_SESSION_KEY_UP, &mut ee_up_key);
    let mut ee_dn_key = [0u8; 32];
    hkdf_expand(&ee_extract, HKDF_INFO_SESSION_KEY_DN, &mut ee_dn_key);

    Ok(SessionSecrets {
        ee_init_key: ClearOnDrop::new(DropCell(KeyMaterial(ee_init_key))),
        ee_token: ClearOnDrop::new(DropCell(KeyMaterial(ee_token))),
        ee_up_key: ClearOnDrop::new(DropCell(KeyMaterial(ee_up_key))),
        ee_dn_key: ClearOnDrop::new(DropCell(KeyMaterial(ee_dn_key))),
    })
}


// Utility functions

fn hkdf(salt: &[u8], key: KeyMaterial, info: &[u8], out: &mut [u8]) {
    let salt_key = ring::hmac::SigningKey::new(&ring::digest::SHA512, salt);
    ring::hkdf::extract_and_expand(&salt_key, &*key, info, out);
}
fn hkdf_extract(salt: &[u8], key: KeyMaterial) -> ring::hmac::SigningKey {
    let salt_key = ring::hmac::SigningKey::new(&ring::digest::SHA512, salt);
    ring::hkdf::extract(&salt_key, &*key)
}

// Take a static private key in byte slice form and return it as an
// EphemeralPrivateKey object along with its public value. This currently
// requires patching *ring* to make the `ec` module and the fields of
// EphemeralPrivateKey public.
fn import_static_key(private_key_bytes: &[u8]) -> Result<(EphemeralPrivateKey, [u8; 32])> {
    use ring::{agreement, ec};
    ensure!(private_key_bytes.len() == 32, "invalid private key length");
    let static_privkey = ec::PrivateKey::from_bytes(
        &agreement::X25519.i.curve,
        untrusted::Input::from(private_key_bytes),
    ).chain_err(|| "import_static_key: import")?;
    let static_privkey = agreement::EphemeralPrivateKey {
        private_key: static_privkey,
        alg: &agreement::X25519,
    };
    let mut static_pubkey = [0u8; 32];
    static_privkey
        .compute_public_key(&mut static_pubkey)
        .chain_err(|| "import_static_key: compute pubkey")?;
    Ok((static_privkey, static_pubkey))
}

// Wrapper around `ring::agreement::agree_ephemeral`.
fn ecdh(my_privkey: EphemeralPrivateKey, peer_pubkey: &[u8]) -> Result<KeyMaterial> {
    ensure!(peer_pubkey.len() == 32, "invalid public key length");
    let peer_pubkey = untrusted::Input::from(&peer_pubkey);
    ring::agreement::agree_ephemeral(
        my_privkey,
        &ring::agreement::X25519,
        peer_pubkey,
        "ecdh: agree_ephemeral".into(),
        |key_material| {
            ensure!(key_material.len() == 32, "invalid ECDH secret length");
            let mut secret = [0u8; 32];
            secret.copy_from_slice(key_material);
            Ok(KeyMaterial(secret))
        },
    )
}

// Wrapper around `ring::aead::seal_in_place`.
fn aead_seal(key: &KeyMaterial, nonce: &[u8], ad: &[u8], in_out: &mut [u8]) -> Result<(usize)> {
    use ring::aead;
    let k = aead::SealingKey::new(&aead::CHACHA20_POLY1305, &**key)
        .chain_err(|| "aead_seal: construct key")?;
    let out_len = aead::seal_in_place(&k, nonce, ad, in_out, 16).chain_err(|| "aead_seal: seal")?;
    Ok((out_len))
}
// Wrapper around `ring::aead::open_in_place`.
fn aead_open<'a>(
    key: &KeyMaterial,
    nonce: &[u8],
    ad: &[u8],
    in_out: &'a mut [u8],
) -> Result<&'a mut [u8]> {
    use ring::aead;
    let k = aead::OpeningKey::new(&aead::CHACHA20_POLY1305, &**key)
        .chain_err(|| "aead_open: construct key")?;
    let msg = aead::open_in_place(&k, nonce, ad, 0, in_out).chain_err(|| "aead_open: open")?;
    Ok(msg)
}


// Tests
#[cfg(test)]
mod tests {
    use super::*;

    const STATIC_PRIVKEY: [u8; 32] = [
        228, 172, 49, 122, 10, 86, 15, 63,
        30, 82, 44, 209, 15, 142, 38, 144,
        20, 110, 164, 245, 17, 109, 59, 27,
        158, 22, 80, 64, 178, 92, 10, 138,
    ];
    const STATIC_PUBKEY: [u8; 32] = [
        85, 215, 107, 196, 200, 26, 154, 112,
        186, 205, 170, 96, 156, 87, 242, 31,
        134, 36, 10, 205, 133, 18, 230, 211,
        38, 179, 240, 57, 75, 251, 43, 122,
    ];

    #[test]
    fn distinct_init_nonces() {
        assert_ne!(CLIENT_INIT_NONCE, SERVER_INIT_NONCE);
    }

    #[test]
    fn keygen() {
        assert!(Client::new(&Random::new()).is_ok());
    }

    #[test]
    fn import_static_key_valid_pubkey() {
        let (_, pubkey) = import_static_key(&STATIC_PRIVKEY)
            .expect("static key import failed");
        assert_eq!(pubkey, STATIC_PUBKEY);
    }

    #[test]
    fn session_secrets_sanity() {
        let (privk, pubk) = import_static_key(&STATIC_PRIVKEY)
            .expect("key import failed");
        let keys = compute_session_secrets(Role::Client, privk, &pubk)
            .expect("compute secrets failed");
        let keys_list = [**keys.ee_init_key, **keys.ee_token,
                    **keys.ee_up_key, **keys.ee_dn_key];

        for k in keys_list.iter() {
            assert_ne!(*k, [0u8; 32]);
        }
        assert_ne!(**keys.ee_init_key, **keys.ee_up_key);
        assert_ne!(**keys.ee_init_key, **keys.ee_dn_key);
        assert_ne!(**keys.ee_up_key, **keys.ee_dn_key);
    }

    #[test]
    fn session_secrets_clear_on_drop() {
        let (privk, pubk) = import_static_key(&STATIC_PRIVKEY)
            .expect("key import failed");
        let keys = compute_session_secrets(Role::Client, privk, &pubk)
            .expect("compute secrets failed");
        assert_ne!(**keys.ee_up_key, [0u8; 32]);
        let cell = ClearOnDrop::into_place(keys.ee_up_key);
        assert_eq!(**cell, [0u8; 32]);
    }

    #[test]
    fn basic_handshake_sanity() {
        let rng = Random::new();
        let mut c = Client::new(&rng).expect("Client::new failed");
        let mut s = Server::new(&rng).expect("Server::new failed");

        s.kx(c.public_key()).expect("S: Key exchange failed");
        c.kx(s.public_key()).expect("C: Key exchange failed");

        let mut challenge_frame = [0u8; 96];
        c.challenge(&STATIC_PUBKEY, &mut challenge_frame)
            .expect("C: Challenge generation failed");
        let mut response_frame = [0u8; 48];
        s.solve_challenge(&STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
            .expect("S: Challenge response failed");
        c.check_response(&mut response_frame)
            .expect("C: Invalid response");

        let (c_up_key, c_dn_key) = c.finish().expect("C: Finish failed");
        let (s_up_key, s_dn_key) = s.finish().expect("S: Finish failed");

        assert_eq!((*c_up_key, *c_dn_key), (*s_up_key, *s_dn_key));
    }

    #[test]
    fn handshake_sanity_with_ad() {
        let rng = Random::new();

        // Client generates key and Message 1 (M1) containing public key,
        // and adds M1's headers to its TX AD hash:
        let mut c = Client::new(&rng).expect("Client::new failed");
        c.update_ad_tx(b"M1 client pubkey headers");
        // C: M1(pubkey) --> S  (Client sends M1 to Server)

        // Server receives M1, generates key, and adds M1's headers to
        // its RX AD hash:
        let mut s = Server::new(&rng).expect("Server::new failed");
        s.update_ad_rx(b"M1 client pubkey headers");

        // Then Server generates M2 containing public key and sends:
        s.update_ad_tx(b"M2 server pubkey headers");
        // S: M2(pubkey) --> C
        c.update_ad_rx(b"M2 server pubkey headers");

        // Both parties compute a key exchange:
        s.kx(c.public_key()).expect("S: Key exchange failed");
        c.kx(s.public_key()).expect("C: Key exchange failed");

        // Client generates and sends challenge message M3:
        c.update_ad_tx(b"M3 client challenge headers");
        let mut challenge_frame = [0u8; 96];
        c.challenge(&STATIC_PUBKEY, &mut challenge_frame)
            .expect("C: Challenge generation failed");
        // C: M3(challenge) --> S
        s.update_ad_rx(b"M3 client challenge headers");

        // Server generates and sends challenge response message M4:
        s.update_ad_tx(b"M4 server response headers");
        let mut response_frame = [0u8; 48];
        s.solve_challenge(&STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
            .expect("S: Challenge response failed");
        // S: M4(response) --> C
        c.update_ad_rx(b"M4 server response headers");

        // Client validates M4
        c.check_response(&mut response_frame)
            .expect("C: Invalid response");

        let (c_up_key, c_dn_key) = c.finish().expect("C: Finish failed");
        let (s_up_key, s_dn_key) = s.finish().expect("S: Finish failed");

        assert_eq!((*c_up_key, *c_dn_key), (*s_up_key, *s_dn_key));
    }

    #[test]
    fn handshake_sanity_with_bad_ad_client() {
        let rng = Random::new();

        let mut c = Client::new(&rng).expect("Client::new failed");
        c.update_ad_tx(b"M1 client pubkey headers");

        let mut s = Server::new(&rng).expect("Server::new failed");
        s.update_ad_rx(b"M1 client pubkey headers");

        s.update_ad_tx(b"M2 server pubkey headers");
        c.update_ad_rx(b"M2 server pubkey headers");

        s.kx(c.public_key()).expect("S: Key exchange failed");
        c.kx(s.public_key()).expect("C: Key exchange failed");

        c.update_ad_tx(b"M3 client challenge headers");
        let mut challenge_frame = [0u8; 96];
        c.challenge(&STATIC_PUBKEY, &mut challenge_frame)
            .expect("C: Challenge generation failed");
        s.update_ad_rx(b"M3 client challenge headers");

        s.update_ad_tx(b"M4 server response headers");
        let mut response_frame = [0u8; 48];
        s.solve_challenge(&STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
            .expect("S: Challenge response failed");
        c.update_ad_rx(b"X4 server response headers");
        // Oops!         ^ X != M

        assert!(c.check_response(&mut response_frame).is_err());
    }

    #[test]
    fn handshake_sanity_with_bad_ad_server() {
        let rng = Random::new();

        let mut c = Client::new(&rng).expect("Client::new failed");
        c.update_ad_tx(b"M1 client pubkey headers");

        let mut s = Server::new(&rng).expect("Server::new failed");
        s.update_ad_rx(b"M1 client pubkey headers");

        s.update_ad_tx(b"M2 server pubkey headers");
        c.update_ad_rx(b"M2 server pubkey headers");

        s.kx(c.public_key()).expect("S: Key exchange failed");
        c.kx(s.public_key()).expect("C: Key exchange failed");

        c.update_ad_tx(b"M3 client challenge headers");
        let mut challenge_frame = [0u8; 96];
        c.challenge(&STATIC_PUBKEY, &mut challenge_frame)
            .expect("C: Challenge generation failed");
        s.update_ad_rx(b"X3 client challenge headers");
        // Oops!         ^ X != M
        s.update_ad_tx(b"M4 server response headers");
        let mut response_frame = [0u8; 48];

        assert!(
            s.solve_challenge(&STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
                .is_err()
        )
    }
}
