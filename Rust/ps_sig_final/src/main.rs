
use signature_core::{error::Error, lib::*};
use signature_ps::{Issuer, MessageGenerators, Prover};

fn main() -> Result<(), Error> {
    let mut rng = rand::thread_rng();
    let num_messages = 4;
    let (public_key, secret_key) = Issuer::new_keys(num_messages, &mut rng)?;

    println!("Key Generation done");
    
    let generators = MessageGenerators::from(&secret_key);
    let nonce = Nonce::random(&mut rng);

    let (context, blinding) =
        Prover::new_blind_signature_context(&mut [][..], &generators, nonce, &mut rng)?;
    let mut messages = [
        (0, Message::hash(b"firstname")),
        (1, Message::hash(b"lastname")),
        (2, Message::hash(b"age")),
        (3, Message::hash(b"allowed")),
    ];

    let blind_signature =
        Issuer::blind_sign(&context, &secret_key, &mut messages[..], nonce)?;

    println!("Signature generation done");

    let signature = blind_signature.to_unblinded(blinding);

    // Remove index
    let messages = [messages[0].1, messages[1].1, messages[2].1, messages[3].1];

    let res = signature.verify(&public_key, messages.as_ref());
    assert_eq!(res.unwrap_u8(), 1);
    println!("Signature Verified");
    Ok(())
}
