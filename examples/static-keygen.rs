extern crate ring;
extern crate untrusted;
extern crate base64;

fn main() {
    use ring::{rand, agreement, ec};

    let rng = rand::SystemRandom::new();
    let curve = &agreement::X25519.i.curve;
    let privkey = ec::PrivateKey::generate(curve, &rng)
        .expect("Key generation failed");

    let mut pubkey_bytes = [0u8; 32];
    privkey.compute_public_key(curve, &mut pubkey_bytes)
        .expect("Public key computation failed");

    let privkey_b64 = base64::encode(privkey.bytes(curve));
    let pubkey_b64 = base64::encode(&pubkey_bytes);

    println!("Private key:\n{}", privkey_b64);
    print32(privkey.bytes(curve));
    println!();
    println!("Public key:\n{}", pubkey_b64);
    print32(&pubkey_bytes);
}

fn print32(a: &[u8]) {
    assert!(a.len() >= 32);
    for i in 0..4 {
        for j in 0..8 {
            print!("{}0x{:02x}{}",
                   if (i,j) == (0,0) {"["} else {" "},
                   a[8*i+j],
                   if (i,j) != (3,7) {","} else {"]"},
            );
        }
        print!("\n");
    }
}
