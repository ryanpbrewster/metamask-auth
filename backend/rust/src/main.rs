use std::time::{Duration, SystemTime};

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
    verify_challenge(&parsed.message)?;
    verify_signature(&parsed.message, &parsed.signature)
}

#[derive(Deserialize)]
struct AuthRequest<'a> {
    message: &'a str,
    signature: &'a str,
}

use lazy_static::lazy_static;
use regex::Regex;
const VALID_CHALLENGE: &str = "^Authenticating for metamask-app.example.com @ ([0-9]+)$";
lazy_static! {
    static ref CHALLENGE_REGEX: Regex = Regex::new(VALID_CHALLENGE).unwrap();
}
const MAX_AGE: Duration = Duration::from_secs(60 * 60 * 24);
pub fn verify_challenge(challenge: &str) -> anyhow::Result<()> {
    let captures = CHALLENGE_REGEX
        .captures(challenge)
        .ok_or_else(|| anyhow!("challenge must match: {}", VALID_CHALLENGE))?;
    let signed_at = captures.get(1).unwrap().as_str().parse::<u64>()?;
    let age = (SystemTime::UNIX_EPOCH + Duration::from_millis(signed_at))
        .elapsed()
        .map_err(|_| anyhow!("challenge is from the future"))?;
    if age > MAX_AGE {
        return Err(anyhow!("challenge is too old: {:?}", age));
    }
    Ok(())
}

use secp256k1::{
    recovery::{RecoverableSignature, RecoveryId},
    Message, PublicKey, Secp256k1,
};

pub fn verify_signature(challenge: &str, signature: &str) -> anyhow::Result<String> {
    if !signature.starts_with("0x") || signature.len() != 132 {
        return Err(anyhow!("signature must start with 0x and be 65 bytes"));
    }
    let rawsig = &hex::decode(&signature[2..])?[..64];

    let secp = Secp256k1::verification_only();
    let msg: Message = message_hash(challenge);
    let sig: RecoverableSignature =
        RecoverableSignature::from_compact(rawsig, RecoveryId::from_i32(0)?)?;
    let pkey = secp.recover(&msg, &sig)?;
    let address = public_key_address(pkey);
    println!(
        "Message: {}\nSignature: {}\nRecovered: {} => {}",
        challenge, signature, pkey, address
    );
    Ok(address)
}

fn message_hash(msg: &str) -> Message {
    let eth_message = format!("\x19Ethereum Signed Message:\n{}{}", msg.len(), msg).into_bytes();
    Message::from_slice(&keccak256(&eth_message)).unwrap()
}

fn public_key_address(pkey: PublicKey) -> String {
    let pkey = pkey.serialize_uncompressed();
    debug_assert_eq!(pkey[0], 0x04);
    let hash = keccak256(&pkey[1..]);
    format!("0x{}", hex::encode_upper(&hash[12..]))
}

pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut output);
    output
}
