use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, RSAKeyParameters, RSAKeyType};
use jsonwebtoken::Header;

pub(super) fn signed_token_and_jwks(
    kid: &str,
    issuer: &str,
    client_id: &str,
    expires_at: u64,
) -> (String, JwkSet) {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use rcgen::{PublicKeyData, SigningKey};

    let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).unwrap();
    let (n, e) = rsa_components_from_der(key_pair.der_bytes()).unwrap();

    let mut jwk = Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            key_id: Some(kid.to_string()),
            key_algorithm: Some(KeyAlgorithm::RS256),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n: URL_SAFE_NO_PAD.encode(strip_leading_zeroes(n)),
            e: URL_SAFE_NO_PAD.encode(strip_leading_zeroes(e)),
        }),
    };
    jwk.common.key_algorithm = Some(KeyAlgorithm::RS256);

    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some(kid.to_string());

    let claims = serde_json::json!({
        "iss": issuer,
        "sub": "user-1",
        "azp": client_id,
        "exp": expires_at,
    });

    let message = [
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()),
    ]
    .join(".");
    let signature = key_pair.sign(message.as_bytes()).unwrap();
    let token = format!("{}.{}", message, URL_SAFE_NO_PAD.encode(signature));
    (token, JwkSet { keys: vec![jwk] })
}

fn strip_leading_zeroes(bytes: &[u8]) -> &[u8] {
    let first_non_zero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[first_non_zero..]
}

fn rsa_components_from_der(der: &[u8]) -> Option<(&[u8], &[u8])> {
    let (tag, body, rest) = der_read_tlv(der)?;
    if tag != 0x30 || !rest.is_empty() {
        return None;
    }

    if let Some(components) = rsa_components_from_sequence(body) {
        return Some(components);
    }

    // SubjectPublicKeyInfo: SEQUENCE { algorithm, BIT STRING public_key }
    let (_, _, after_algorithm) = der_read_tlv(body)?;
    let (bit_string_tag, bit_string, _) = der_read_tlv(after_algorithm)?;
    if bit_string_tag != 0x03 || bit_string.first().copied()? != 0 {
        return None;
    }
    let (inner_tag, inner_body, inner_rest) = der_read_tlv(&bit_string[1..])?;
    if inner_tag != 0x30 || !inner_rest.is_empty() {
        return None;
    }
    rsa_components_from_sequence(inner_body)
}

fn rsa_components_from_sequence(sequence: &[u8]) -> Option<(&[u8], &[u8])> {
    let (n_tag, n, after_n) = der_read_tlv(sequence)?;
    let (e_tag, e, after_e) = der_read_tlv(after_n)?;
    if n_tag == 0x02 && e_tag == 0x02 && after_e.is_empty() {
        Some((n, e))
    } else {
        None
    }
}

fn der_read_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, input) = input.split_first()?;
    let (&length_byte, input) = input.split_first()?;
    let (length, input) = if length_byte & 0x80 == 0 {
        (usize::from(length_byte), input)
    } else {
        let length_octets = usize::from(length_byte & 0x7f);
        if length_octets == 0 || length_octets > std::mem::size_of::<usize>() {
            return None;
        }
        let (length_bytes, input) = input.split_at_checked(length_octets)?;
        let length = length_bytes
            .iter()
            .fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (length, input)
    };
    let (body, rest) = input.split_at_checked(length)?;
    Some((tag, body, rest))
}
