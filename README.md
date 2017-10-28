# nnshake

A [Rust] implementation of a simple Elliptic Curve Diffie-Hellman
([ECDH]) [channel-binding] handshake protocol, based on [X25519] and
[ChaCha20-Poly1305], for establishing [forward-secure] encrypted and
authenticated sessions between endpoints such as clients and servers.

This is **experimental software**. It has not received formal security
review and should not be entrusted with sensitive data. Use at your own
risk.

[Rust]: https://www.rust-lang.org/
[ECDH]: https://en.wikipedia.org/wiki/ECDH
[channel-binding]: https://tools.ietf.org/html/rfc5056
[X25519]: https://tools.ietf.org/html/rfc7748
[ChaCha20-Poly1305]: https://tools.ietf.org/html/rfc7539
[forward-secure]: https://en.wikipedia.org/wiki/Forward_secrecy

## Overview

This crate implements functions for performing a two-phase handshake
between two endpoints. The phases of the handshake are:

1. **kx** ([ephemeral] ECDH key exchange/agreement)
2. **auth** (Peer authentication)

The **kx** phase establishes an encrypted session in the form of a
symmetric keypair shared by the two endpoints. This keypair can be used
for bidirectional encrypted data transfer. However, at the end of this
phase, the session is *entirely unauthenticated*—the endpoints may be
talking to an [MITM] attacker rather than to each other.

The **auth** phase allows each endpoint to confirm the identity of the
other using an authentication method. This phase is tied to the **kx**
phase using *channel binding*. In addition to a shared symmetric
keypair, the **kx** phase produces a shared secret *channel binding
token*. This token is used in the **auth** phase to link the
authentication with the encrypted session. This two-phase approach
separates the concerns of *establishing encrypted sessions* and
*authentication*, allowing for a range of different authentication
mechanisms.

This library does not perform any I/O; it just accepts byte slices from
the user for input and output. As such, it can easily be embedded in
higher-level protocols and network applications.

The following cryptographic primitives are used in the current version:

- [X25519] \(RFC 7748) for ECDH key agreement
- [ChaCha20-Poly1305] \(RFC 7539) for [AEAD] symmetric encryption
- [HKDF] \(RFC 5869) with HMAC-SHA-512 (using fixed-length salt) for key
  derivation
- [BLAKE2b] for hashing of user-supplied additional data

There is, by design, no provision made for negotiating or using
different primitives. The *[ring]* library is used for all primitives
except BLAKE2b.

[ephemeral]: https://en.wikipedia.org/wiki/Ephemeral_key
[MITM]: https://en.wikipedia.org/wiki/Man-in-the-middle_attack
[AEAD]: https://en.wikipedia.org/wiki/AEAD
[HKDF]: https://tools.ietf.org/html/rfc5869
[BLAKE2b]: https://blake2.net/
[ring]: https://github.com/briansmith/ring

## Protocol

Call the endpoints Alice (*A*) and Bob (*B*). Assume that Alice is the
initiator of the session.

### kx phase

1. Alice generates an ephemeral ECDH key **a** for this session with
   corresponding public key **a.pub**.
   
2. Alice sends **a.pub** to Bob.

3. When Bob receives **a.pub**, he generates an ephemeral key **b**.

4. Bob sends **b.pub** to Alice.

That is:

A: **a.pub** → B\
B: **b.pub** → A

5. Both parties compute _k_ = *ECDH(a, b.pub)* = *ECDH(b, a.pub)*.

6. Both parties use _k_ to derive:
   - a shared pair of symmetric keys (**up**, **dn**). The *upstream
     key* **up** is used for encryption by the session initiator Alice
     (hence for decryption by Bob), and vice-versa for the downstream
     key **dn**.
   - A shared channel-binding token **t**.

### auth phase

This phase allows one or both endpoints to authenticate the other via
some authentication mechanism that makes use of the channel-binding
token **t** derived in the **kx** phase. Many different such mechanisms
are possible, and they can be flexibly combined in different ways.

### Example 1: Authentication Using a Static Public Key

Suppose Alice is a client and Bob is a server with a well-known static
ECDH public key **bs.pub**. Alice can verify she is really talking to
Bob as follows:

Let *E_k(m)* denote symmetric encryption of message _m_ with key *k*.

1. Alice generates a random *challenge code* **r** and an ephemeral ECDH
   *challenge key* **c** / **c.pub**. This key will be used only to
   encrypt a single message to Bob.
   
2. Alice computes _cs_ = *ECDH(c, bs.pub)*.

3. Alice sends <i> E_up(**c.pub**, E_cs(**r** ^ **t**)) </i> to
   Bob. That is, she takes the XOR of the challenge code and the channel
   binding token, encrypts it under the key *cs*, prepends **c.pub**,
   and sends to Bob (encrypted under the upstream session key **up**).
   
4. Bob receives and unwraps this message, computes _cs_ = *ECDH(bs,
   c.pub)*, unwraps the inner message <i>**r** ^ **t**</i> with *cs*,
   and XORs it with **t**, yielding **r**.
   
5. Bob sends <i> E_dn(**r**) </i> to Alice.

6. Alice receives and unwraps this message, and verifies that the
   received value of **r** matches the one she generated in Step 1.

That is:

A: <i> E_up(**c.pub**, E_cs(**r** ^ **t**)) </i> → B\
B: <i> E_dn(**r**) → A </i>

This protocol works because if Mallory is an MITM between Alice and Bob,
then she can't unwrap the inner message (because it's encrypted using
Bob's static public key **bs.pub**); and if she forwards it to Bob, then
the token Bob uses to perform the XOR in Step 4 will be the binding
token for his channel with Mallory, instead of the token he shares with
Alice. The response he sends in Step 5 will thus fail Alice's
verification in Step 6.

(This protocol was proposed by [@eternaleye] and inspired by
[TCPcrypt].)

[@eternaleye]: https://github.com/eternaleye
[TCPcrypt]: http://tcpcrypt.org/

### Example 2: Authentication Using a Pre-Shared Key

Suppose Alice and Bob share an authentication key **K**. Then one party
can authenticate to the other by sending *E(H(__K__, __t__))*, where *E*
is the session encryption and _H(key, message)_ is a suitable
cryptographic keyed hash or [HMAC] function.

[HMAC]: https://en.wikipedia.org/wiki/HMAC

### Example 3: Hash Puzzles

Suppose Alice is requesting a service from Bob. Bob may wish to
rate-limit such requests and ensure "good faith" on the part of clients
to mitigate denial-of-service attacks. Bob can "authenticate" Alice by
sending a [hash puzzle] to Alice that requires knowledge of the binding
token **t** to solve, ensuring any solution he receives is really
provided by Alice.

[hash puzzle]: https://en.wikipedia.org/wiki/Proof-of-work_system

## Example Usage

Currently this crate only implements static public key
authentication. Here's a basic example that shows the complete handshake
for both client and server:

```rust
extern crate nnshake;

// A static keypair can be generated with examples/static-keygen
const SERVER_STATIC_PRIVKEY: [u8; 32] = [
    228, 172, 49, 122, 10, 86, 15, 63,
    30, 82, 44, 209, 15, 142, 38, 144,
    20, 110, 164, 245, 17, 109, 59, 27,
    158, 22, 80, 64, 178, 92, 10, 138,
];
const SERVER_STATIC_PUBKEY: [u8; 32] = [
    85, 215, 107, 196, 200, 26, 154, 112,
    186, 205, 170, 96, 156, 87, 242, 31,
    134, 36, 10, 205, 133, 18, 230, 211,
    38, 179, 240, 57, 75, 251, 43, 122,
];

fn main() {
    use nnshake::{Random, Client, Server};
    let rng = Random::new();

    // Message 1: Client generates key and sends pubkey to server
    let mut c = Client::new(&rng).expect("Client keygen failed");

    // Message 2: Server receives client pubkey, generates key and
    // sends pubkey to client
    let mut s = Server::new(&rng).expect("Server keygen failed");

    // Both parties compute ECDH key exchange to derive a shared session key
    s.kx(c.public_key()).expect("S: Key exchange failed");
    c.kx(s.public_key()).expect("C: Key exchange failed");

    // Message 3: Client generates a challenge message to authenticate
    // server based on its static public key, and sends to server
    let mut challenge_frame = [0u8; 96];
    c.challenge(&SERVER_STATIC_PUBKEY, &mut challenge_frame)
        .expect("C: Challenge generation failed");

    // Message 4: Server receives challenge, generates response, and
    // sends to client
    let mut response_frame = [0u8; 48];
    s.solve_challenge(&SERVER_STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
        .expect("S: Challenge solution failed");

    // Client receives and validates server's response message
    c.check_response(&mut response_frame).expect("C: Invalid response");

    // Client and server now share a pair of keys (upstream, downstream)
    // that can be used for symmetric AEAD data transfer
    let (c_up_key, c_dn_key) = c.finish().expect("C: Finish failed");
    let (s_up_key, s_dn_key) = s.finish().expect("S: Finish failed");

    assert_eq!((*c_up_key, *c_dn_key), (*s_up_key, *s_dn_key));
}
```

## Notes

- The API is simple and hard to misuse. Each of the main handshake
  methods can only be called when the handshake is at the appropriate
  step, and upon success, each transitions the handshake to the next
  step.

- When the handshake finishes, a pair `(upstream, downstream)` of keys
  is returned. The intent is that `upstream` is used for client→server
  encryption (encryption by the client and decryption by the server),
  and that `downstream` is used conversely.

- The library itself does not use the `upstream` and `downstream` keys,
  but rather derives its own for use in the challenge and response
  steps. This is to ensure that all AEAD nonce values can safely be used
  by the user after the handshake finishes.

- Support is provided for supplying additional data during the handshake
  via the `update_ad_tx()` and `update_ad_rx()` methods. These methods
  should be used at every step to include any transmitted and received
  cleartext message headers in the respective hash state. This provides
  security against alteration of the cleartext headers of messages in
  transit. If such alteration occurs, the tx hash of the sender will
  fail to match the rx hash of the receiver. Since this hash is passed
  as *additional data* during symmetric AEAD encryption and decryption,
  non-matching hashes will cause a handshake failure when attempting to
  decrypt Message 3 or Message 4. See the
  [simple-ad](examples/simple-ad.rs) example.

- Some care is taken to ensure that stack memory containing sensitive
  key material is cleared after use. The `upstream` and `downstream`
  keys returned to the user when the handshake finishes are wrapped in a
  struct that clears its contents when dropped. This struct implements
  `Deref`, so the array of key bytes can be accessed with the `*`
  operator.

- A [static-keygen](examples/static-keygen.rs) tool is provided in the
  examples that can be used to generate static ECDH keypairs. This tool
  will print the private and public keys in Base64 and hex format.

## Building

Currently (Oct 2017) the *ring* crate does not support [static ECDH
keys](https://github.com/briansmith/ring/issues/331).  Therefore,
building this crate requires applying a small [patch](ring.diff) to a
local copy of *ring*. This patch just makes a few *ring* datatypes
public instead of private:

```shell
$ git clone https://github.com/doomsparkles/nnshake
$ cd nnshake
$ git clone https://github.com/briansmith/ring
$ (cd ring ; git apply ../ring.diff)
$ cargo build --examples
```

## License

Distributed under the [MIT License](LICENSE).
