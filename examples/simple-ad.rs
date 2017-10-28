extern crate nnshake;

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
    c.challenge(&SERVER_STATIC_PUBKEY, &mut challenge_frame)
        .expect("C: Challenge generation failed");
    // C: M3(challenge) --> S
    s.update_ad_rx(b"M3 client challenge headers");

    // Server generates and sends challenge response message M4:
    s.update_ad_tx(b"M4 server response headers");
    let mut response_frame = [0u8; 48];
    s.solve_challenge(&SERVER_STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
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
