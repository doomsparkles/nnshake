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
