use anyhow::anyhow;
use serde::Deserialize;
use warp::{filters, http::header, hyper::StatusCode, reply::with_status, Filter};

#[tokio::main]
async fn main() {
    let handler = warp::any()
        .and(filters::header::optional(header::AUTHORIZATION.as_str()))
        .map(auth_handler)
        .with(
            warp::cors()
                .allow_any_origin()
                .allow_method("POST")
                .allow_header(header::AUTHORIZATION.as_str()),
        );

    warp::serve(handler).run(([127, 0, 0, 1], 3030)).await;
}

fn auth_handler(auth: Option<String>) -> impl warp::Reply {
    match verify_auth(auth.as_deref()) {
        Ok(addr) => with_status(addr, StatusCode::OK),
        Err(err) => with_status(format!("invalid: {}", err), StatusCode::BAD_REQUEST),
    }
}

fn verify_auth(auth: Option<&str>) -> anyhow::Result<String> {
    println!("checking header: {:?}", auth);
    let header = auth.ok_or_else(|| anyhow!("no auth"))?;
    let raw = header
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow!("authorization header must start with Bearer"))?;
    let decoded = base64::decode(raw)?;
    let parsed: AuthRequest = serde_json::from_slice(&decoded)?;
    verify_signature(&parsed.message, &parsed.signature)
}

#[derive(Deserialize)]
struct AuthRequest<'a> {
    message: &'a str,
    signature: &'a str,
}

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
