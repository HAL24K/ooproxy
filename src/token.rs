/// OOProxy - An OpenID and OAuth2 reverse proxy
/// Copyright (C) 2018  HAL24000 B.V.
/// 
/// This program is free software: you can redistribute it and/or modify
/// it under the terms of the GNU General Public License as published by
/// the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
/// 
/// This program is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU General Public License for more details.
/// 
/// You should have received a copy of the GNU General Public License
/// along with this program.  If not, see <https://www.gnu.org/licenses/>.
 
use actix_web::Error;
use error::{ErrorForbidden, ErrorInternalServerError};
use bytes::Bytes;
use jsonwebtoken::{decode, decode_header, Algorithm, Validation};
use serde_json::Value;
use std::str;
use collections::HashMap;
use cmp::{Eq, PartialEq};
use hash::{Hash, Hasher};
use str::FromStr;

#[derive(Clone, Copy)]
/// A wrapper around the token algorithm that adds hashing, eq, fromstr parsing, and methods that determine wheter it's a symmetric or asymmetric algorithm
pub struct WrappedAlgorithm(pub Algorithm);

impl WrappedAlgorithm {
    pub fn is_symmetric(self) -> bool {
        self.0 == Algorithm::HS256 ||
        self.0 == Algorithm::HS384 ||
        self.0 == Algorithm::HS512
    }

    pub fn is_asymmetric(self) -> bool {
        !self.is_symmetric()
    }
}

impl PartialEq for WrappedAlgorithm {
    fn eq(&self, other: &WrappedAlgorithm) -> bool {
        self.0 == other.0
    }
}

impl Eq for WrappedAlgorithm {}

impl Hash for WrappedAlgorithm {
    fn hash<H: Hasher>(&self, state: &mut H) {
        (self.0 as i32).hash(state);
    }
}

impl FromStr for WrappedAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "RS512" => Ok(Algorithm::RS512),
            "RS256" => Ok(Algorithm::RS256),
            "RS384" => Ok(Algorithm::RS384),
            "HS512" => Ok(Algorithm::HS512),
            "HS256" => Ok(Algorithm::HS256),
            "HS384" => Ok(Algorithm::HS384),
            _ => Err(ErrorInternalServerError("unable to parse algorithm"))
        }.map(WrappedAlgorithm)
    }
}

/// Validate a jwt token with the available signing keys
///
/// # Arguments
/// 
/// * `token_str` - The jwt token
/// * `secret` - The client secret, if relevant
/// * `keys` - The set of assymmetric signing keys
pub fn validate_token(token_str: &str, secret: &Option<Bytes>, keys: &HashMap<WrappedAlgorithm, HashMap<String, Bytes>>, validation: &Validation) -> Result<(), Error> {
    let header = decode_header(&token_str).map_err(|e| ErrorForbidden(format!("unable to decode token header: {}", e)))?;
    if WrappedAlgorithm(header.alg).is_symmetric() {
        validate_token_symmetric(token_str, secret, validation)
    } 
    else {
        validate_token_asymmetric(token_str, header.alg, keys, validation, &header.kid)
    }
}

/// Retrieve the jwt token from the authorization header 
/// 
/// # Arguments
/// 
/// * `header_str` -> The contents of the authorization header
pub fn get_token_str(header_str: &str) -> Result<String, Error> {
    match (header_str.get(0..7), header_str.get(7..)) {
        (Some("Bearer "), Some(token)) => Ok(token.to_string()),
        _ => Err(ErrorForbidden("no bearer token in authorization header"))
    }
}

/// Check if we're missing a signing key, by decoding the token
/// 
/// # Arguments
/// 
/// * `token_str` - The jwt token  to check
/// * `keys` - The available signing keys
pub fn has_missing_kid(token_str: &str, keys: &HashMap<WrappedAlgorithm, HashMap<String, Bytes>>) -> bool {
    decode_header(token_str)
        .ok()
        .and_then(|header| {
            let wrapped_alg = WrappedAlgorithm(header.alg);
            if wrapped_alg.is_asymmetric() {
                header.kid
                      .and_then(|id| keys.get(&wrapped_alg).map(|inner_map| !inner_map.contains_key(&id)))
            }
            else {
                Some(false)
            }
        }).unwrap_or(false)
}

/// Validate the token with a symmetric key (the client secret)
fn validate_token_symmetric(token_str: &str, secret: &Option<Bytes>, validation: &Validation) -> Result<(), Error> {
    let inner_secret = secret.as_ref().ok_or_else(|| ErrorInternalServerError("client secret not configured, symmetric token decryption not possible"))?;
    validate_token_with_key(token_str, &inner_secret, validation)
}

/// Validate the token with a asymetric (RSA) key
fn validate_token_asymmetric(token_str: &str, alg: Algorithm, keys: &HashMap<WrappedAlgorithm, HashMap<String, Bytes>>, validation: &Validation, kid: &Option<String>) -> Result<(), Error> {
    let key_map = keys.get(&WrappedAlgorithm(alg)).ok_or_else(|| ErrorForbidden("no key available for token algorithm"))?;
    if let Some(id) = kid { // Decode with the provided key id
        let key = key_map.get(id).ok_or_else(|| ErrorForbidden("unknown key id"))?;
        validate_token_with_key(&token_str, &key, validation)
    }
    else { // Try to decode with all keys
        for key in key_map.values() {
            if validate_token_with_key(&token_str, &key, validation).is_ok() {
                return Ok(())
            }
        }
        Err(ErrorForbidden("unable to validate token with available signing keys"))
    }
}

/// Validate the token a key, either symmetric or assymetric
fn validate_token_with_key(token_str: &str, key: &Bytes, validation: &Validation) -> Result<(), Error> {
    decode::<Value>(&token_str, key, &validation).map_err(|e| ErrorForbidden(format!("error validating token: {}", e)))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64;
    use serde_json::Value;

    static TOKEN: &'static str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVBMkZDNkU5NUFFQ0NEN0QxMUE0NUY4ODVGQkVBOTI1MkIxODUxRjUiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJXaV9HNlZyc3pYMFJwRi1JWDc2cEpTc1lVZlUifQ.eyJuYmYiOjE1MzYyMzMyMjYsImV4cCI6MTUzNjIzNjgyNiwiaXNzIjoiaHR0cDovL2lkZW50aXR5IiwiYXVkIjpbImh0dHA6Ly9pZGVudGl0eS9yZXNvdXJjZXMiLCJhcGkxIl0sImNsaWVudF9pZCI6ImNsaWVudCIsInNjb3BlIjpbImFwaTEiXX0.n8_d8DrscYy8h0pEtlispSjqeVyJLIIQdsB-FeSTG9xiszDBNtBD3l_pzdVwrPpga5aDhTbz6vkzzqiU3YkwOYie4S7rvOre0jjFQ3-DnWlhYYf4ii54k40T9mH_AJV1pYR9SxEefCp78PYbpHNqEG2p5v8cFj0lDDcdTMglaRKkTOX43SdxRXr-Ww8WRjpEsF1tMwOhaK1LJolNR-waf9NXbfzssNdmYEzQ-gpVuEe6aJuMsfWuJ3LO2KzxnJnSw53DXGCTDRV16qNv9vAaDWNpFvSbwghLEo4JQCdX8bMRX2ysW2YGwBno-8nOkMEzfi6SKJ-5zDebOQhSKQ_86w";
    static INVALID_TOKEN: &'static str = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjVBMkZDNkU5NUFFQ0NEN0QxMUE0NUY4ODVGQkVBOTI1MkIxODUxRjUiLCJ0eXAiOiJKV1QiLCJ4NXQiOiJXaV9HNlZyc3pYMFJwRi1JWDc2cEpTc1lVZlUifQ.eyJuYmYiOjE1MzYyMzMyMjYsImV4cCI6MTUzNjIzNjgyNiwiaXNzIjoiaHR0cDovL2lkZW50aXR5IiwiYXVkIjpbImh0dHA6Ly9pZGVudGl0eS9yZXNvdXJjZXMiLCJhcGkxIl0sImNsaWVudF9pZCI6ImNsaWVudCIsInNjb3BlIjpbImFwaTEiXX0.n8_d8DrscYy8h0pEtlispSjqeVyJLIIQdsB-FeSTG9xiszDBNtBD3l_pzdVwrPpga5aDhTbz6vkzzqiU3YkwOYie4S7rvOre0jjFQ3-DnWlhYYf4ii54k40T9mH_AJV1pYR9SxEefCp78PYbpHNqEG2p5v8cFj0lDDcdTMglaRKkTOX43SdxRXr-Ww8WRjpEsF1tMwOhaK1LJolNR-waf9NXbfzssNdmYEzQ-gpVuEe6aJuMsfWuJ3LO2KzxnJnSw53DXGCTDRV16qNv9vAaDWNpFvSbwghLEo4JQCdX8bMRX2ysW2YGwBno-8nOkMEzfi6SKJ-5zDebOEhSKQ_86w";
    static KID: &'static str = "5A2FC6E95AECCD7D11A45F885FBEA9252B1851F5";
    static KEY: &'static str = "MIIBCgKCAQEAviuRydGmSbij9PpVMEZdy29J0Ae/M883JTORRfcsKvEM1T0gdYIyX23vq86vSkmlQVOiiK++5U9HgmNm0lMojQC2KC7Gtkfh1uD7AQxDo1TBRT0BqxcBxrzyJ308AT5aiLnFVYlf4f0fvdIJZ+KAyXvAQAXLN3PwksFcYAVavGy402MzLNaqWAZ2iQ0+MD0mLfgCZItjkVbX5hvOZ9q2ZlRsw33bLttEguord12BY025yzBiZOGOZVZxEw8Ngz3gs4J23wxXpeeMUDvArPRi7se8Jev26/E8I0J77ttiuScbVDqX+lDYShsKGTDWxUcpVeqBvSk6GL+gxbPdogIokQIDAQAB";

    #[test]
    fn test_token_decode() {
        let mut key_map: HashMap<String, Bytes> = HashMap::new();
        key_map.insert(KID.to_string(), Bytes::from(base64::decode(KEY).unwrap()));
        let mut keys: HashMap<WrappedAlgorithm, HashMap<String, Bytes>> = HashMap::new();
        keys.insert(WrappedAlgorithm(Algorithm::RS256), key_map);

        let validation = Validation {
            // Token can be expired, we don't want to make the test time-dependent
            validate_exp: false, 
            validate_iat: false, 
            validate_nbf: false, 
            leeway: 0,
            aud: Some(
                Value::Array(
                    vec![
                        Value::String("http://identity/resources".to_string()), 
                        Value::String("api1".to_string())])),
            iss: Some("http://identity".to_string()), 
            sub: None, 
            algorithms: vec![Algorithm::RS256]
        };
        let validated = validate_token(TOKEN, &None, &keys, &validation);
        println!("{:?}", validated);
        assert!(validated.is_ok());

        let not_validated = validate_token(INVALID_TOKEN, &None, &keys, &validation);
        assert!(not_validated.is_err());
    }
}