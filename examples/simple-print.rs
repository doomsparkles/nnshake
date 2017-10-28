extern crate nnshake;

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for b in bytes {
        write!(&mut s, "{:02x} ", b).expect("Unable to write");
    }
    s
}

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

    // Generate ephemeral keys
    let mut c = Client::new(&rng).expect("Client keygen failed");
    println!("C: Ephemeral pubkey =\n{}", to_hex(c.public_key()));
    let mut s = Server::new(&rng).expect("Server keygen failed");
    println!("S: Ephemeral pubkey =\n{}\n", to_hex(s.public_key()));

    // Key exchange
    s.kx(c.public_key()).expect("S: Key exchange failed");
    c.kx(s.public_key()).expect("C: Key exchange failed");

    // Challenge and response
    let mut challenge_frame = [0u8; 96];
    c.challenge(&SERVER_STATIC_PUBKEY, &mut challenge_frame)
        .expect("C: Challenge generation failed");
    println!("C: Challenge frame =\n{}", to_hex(&challenge_frame));

    let mut response_frame = [0u8; 48];
    s.solve_challenge(&SERVER_STATIC_PRIVKEY, &mut challenge_frame, &mut response_frame)
        .expect("S: Challenge solution failed");
    println!("S: Response frame =\n{}\n", to_hex(&response_frame));

    match c.check_response(&mut response_frame) {
        Ok(()) => println!("C: Good response"),
        Err(e) => println!("C: Invalid response ({})", e),
    }

    let (c_up_key, c_dn_key) = c.finish().expect("C: Finish failed");
    let (s_up_key, s_dn_key) = s.finish().expect("S: Finish failed");
    println!("C: Session keys =\n up: {}\n dn: {}",
             to_hex(&*c_up_key), to_hex(&*c_dn_key));
    println!("S: Session keys =\n up: {}\n dn: {}",
             to_hex(&*s_up_key), to_hex(&*s_dn_key));
}
