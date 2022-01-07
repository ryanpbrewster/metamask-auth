use warp::Filter;
use serde::Deserialize;

#[tokio::main]
async fn main() {
    let hello = warp::any()
        .and(warp::header("authorization"))
        .map(|header: String| {
            match verify_auth(&header) {
                Ok(_) => warp::reply::with_status("ok", warp::http::StatusCode::OK),
                Err(err) => {
                    eprintln!("{}", err);
                    warp::reply::with_status("invalid", warp::http::StatusCode::BAD_REQUEST)
                }
            }
        });

    warp::serve(hello).run(([127, 0, 0, 1], 3030)).await;
}

fn verify_auth(header: &str) -> anyhow::Result<String> {
    let auth: AuthRequest = serde_json::from_str(header)?;
    Ok(verify_signature(&auth.message, &auth.signature)?)
}

#[derive(Deserialize)]
struct AuthRequest {
    message: String,
    signature: String,
}

use anyhow::anyhow;
use secp256k1::{
    recovery::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};

pub fn verify_signature(challenge: &str, signature: &str) -> anyhow::Result<String> {
    if !signature.starts_with("0x") || signature.len() != 132 {
        return Err(anyhow!("signature must start with 0x and be 65 bytes"));
    }
    let signature = &hex::decode(&signature[2..])?[..64];

    let secp = Secp256k1::verification_only();
    let message: Message = message_hash(challenge);
    let signature: RecoverableSignature =
        RecoverableSignature::from_compact(signature, RecoveryId::from_i32(0)?)?;
    let actual_pkey = secp.recover(&message, &signature)?;
    Ok(public_key_address(actual_pkey))
}

fn message_hash(msg: &str) -> Message {
    let eth_message = format!("\x19Ethereum Signed Message:\n{}{}", msg.len(), msg).into_bytes();
    Message::from_slice(&keccak256(&eth_message)).unwrap()
}

fn public_key_address(pkey: PublicKey) -> String {
    let pkey = pkey.serialize_uncompressed();
    debug_assert_eq!(pkey[0], 0x04);
    let hash = keccak256(&pkey[1..]);
    hex::encode_upper(&hash[12..])
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}