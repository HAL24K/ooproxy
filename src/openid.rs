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

use actix_web::{client, Error, HttpMessage};
use bytes::{Bytes, BytesMut, BufMut};
use futures;
use base64;
use serde_json;
use futures::Future;
use num::BigInt;
use num::bigint::Sign;
use std::{str, mem};
use std::iter::Iterator;
use serde::Deserialize;
use crate::collections::HashMap;
use crate::error::ErrorInternalServerError;
use crate::token::WrappedAlgorithm;

/// The resulting information from retrieving and parsing the OpenID endpoints, contains the issuer and signing keys
pub struct OpenIDInfo {
    pub issuer: String,
    pub keys: HashMap<WrappedAlgorithm, HashMap<String, Bytes>>
}

#[derive(Deserialize)]
/// A deserialized OpenID discovery document
struct OpenIDConnectDiscovery {
    jwks_uri: String,
    issuer: String,
}

#[derive(Deserialize)]
/// A deserialized JSON web key
struct JSONWebKey {
    alg: String,
    kid: Option<String>,
    kty: String,
    #[serde(rename="use")]
    usage: Option<String>,
    key_ops: Option<Vec<String>>,
    e: Option<String>,
    n: Option<String>
}

#[derive(Deserialize)]
/// A deserialized JSON web key set
struct JSONWebKeySet {
    keys: Vec<JSONWebKey>
}

/// Query the discovery and jwks endpoints for the provider and:
/// 
/// * Retrieve the issuer identity
/// * Retrieve and parse a set of signing public keys that can be used to verify jwt tokens
/// 
/// # Arguments
/// 
/// * `discovery_url` - The discovery url of the provider
pub fn openid_connect_retrieve(discovery_url: &str) -> impl Future<Item = OpenIDInfo, Error = Error> {
    openid_connect_retrieve_discovery(discovery_url)
        .and_then(|discovery| {
            openid_connect_retrieve_jwks(&discovery.jwks_uri).map(|keyset| {
                OpenIDInfo { issuer: discovery.issuer, keys: keyset }
            })
        })
        .map_err(|e| ErrorInternalServerError(format!("error retrieving signing keys through openid: {}", e)))
}

/// Retrieve the OpenID discovery document, and then parse it
fn openid_connect_retrieve_discovery(discovery_url: &str) -> impl Future<Item = OpenIDConnectDiscovery, Error = Error> {
    futures::done(client::ClientRequest::get(discovery_url).finish())
        .and_then(|req| req.send().map_err(Error::from))
        .and_then(|resp| {
            resp.body()
                .map_err(Error::from)
                .and_then(|body| parse_discovery(&body))
        })
}

/// Parsing part of an OpenID Discovery document: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig
/// 
/// # Arguments
/// * `body` -> the discovery response body
fn parse_discovery(body: &Bytes) -> Result<OpenIDConnectDiscovery, Error> {
    serde_json::from_slice(body).map_err(Error::from)
}

/// Retrieve the openid jwks uri, and decode it into a set of keys that can be used to verify signatures
fn openid_connect_retrieve_jwks(jwks_uri: &str) -> impl Future<Item = HashMap<WrappedAlgorithm, HashMap<String, Bytes>>, Error = Error> {
    futures::done(client::ClientRequest::get(jwks_uri).finish())
            .and_then(|req| req.send().map_err(Error::from))
            .and_then(|resp| resp.body().map_err(Error::from))
            .and_then(|body| decode_web_keyset(&body))
}

/// We're:
/// 
/// * Parsing a JSON Web Key Set document: https://tools.ietf.org/html/rfc7517
/// * Filtering out the web keys we can't use
/// * Parsing the signing keys
/// * Putting those in a hashmap we can use to decode tokens
/// * Returning a set of signing keys
/// 
/// # Arguments
/// 
/// * `jwt_str` - The retrieved jwk document
fn decode_web_keyset(jwk_str: &Bytes) -> Result<HashMap<WrappedAlgorithm, HashMap<String, Bytes>>, Error> {
    let key_set: JSONWebKeySet = 
        serde_json::from_slice(jwk_str)
                .map_err(|e| ErrorInternalServerError(format!("failed decoding web keys: {}", e)))?;

    let mut key_map: HashMap<WrappedAlgorithm, HashMap<String, Bytes>> = HashMap::with_capacity(2);

    let mut i = ::std::i32::MIN;
    for (web_key, alg) in get_usable_web_keys(key_set) {
        let wk = decode_web_key(&web_key)?;
        let inner_map = key_map.entry(alg).or_insert_with(HashMap::new);
        inner_map.insert(web_key.kid.unwrap_or(i.to_string()), wk);
        i = i + 1;
    }

    Ok(key_map)
}

/// Filter the set of web keys so that we can retrieve the keys we can use to validate signatures
fn get_usable_web_keys(key_set: JSONWebKeySet) -> impl Iterator<Item = (JSONWebKey, WrappedAlgorithm)> {
    key_set.keys
           .into_iter()
           .filter(|web_key| web_key.kty == "RSA" &&
                               web_key.usage.as_ref().map(|us| us == "sig").unwrap_or(true) &&
                               web_key.key_ops.as_ref().map(|ko| ko.iter().any(|k| k == "verify")).unwrap_or(true))
           .map(|web_key| (web_key.alg.parse::<WrappedAlgorithm>(), web_key))
           .filter(|(alg, _)| alg.as_ref().map(|a| a.is_asymmetric()).unwrap_or(false))
           .map(|(alg, web_key)| (web_key, alg.unwrap()))
}

/// The key has to go from the JWK format to the ASN.1 DER RSAPublicKey format:
/// 
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
///
/// Relevant standards: 
/// 
/// * RSAPublicKey: https://tools.ietf.org/html/rfc3447#appendix-A.1.1
/// * ASN.1 DER https://www.itu.int/rec/T-REC-X.690-201508-I/en
/// * JSON Web Algorithms: https://www.rfc-editor.org/rfc/rfc7518.txt
///
/// # Arguments
/// * `key` - The decoded JSON Web Key to convert to RSAPublicKey format
fn decode_web_key(key: &JSONWebKey) -> Result<Bytes, Error> {
    match (decode_base64urloption(&key.n), decode_base64urloption(&key.e)) {
        (Some(modulus), Some(exponent)) => {
            Ok(encode_asn1_der_rsapublickey(&modulus, &exponent))
        }, 
        _ => Err(ErrorInternalServerError("web key is missing information"))
    }
}

/// Decode a base64url-encoded string to a byte vector
fn decode_base64urloption(o: &Option<String>) -> Option<Vec<u8>> {
    let inner = o.as_ref()?;
    base64::decode_config(inner, base64::URL_SAFE).ok()
}

/// Encode a RSAPublicKey with ASN.1 DER
/// 
/// # Arguments
/// * `n` - Modulus, big endian unsigned encoded byte array
/// * `e` - Exponent, big endian unsigned encoded byte array
fn encode_asn1_der_rsapublickey(n: &[u8], e: &[u8]) -> Bytes {
    const CONSTRUCTED_SEQUENCE_TAG: u8 = 0x10 | 0x20;
    const INTEGER_TAG: u8 = 0x2;

    let int_buffers = 
        [
            int_be_from_unsigned_to_signed(n), 
            int_be_from_unsigned_to_signed(e)
        ];
    let inner_sequence_len = 
        int_buffers.iter()
                   .map(|buff| buff.len() + asn1_length_size(buff.len()) + 1)
                   .sum();
    let total_len = inner_sequence_len + asn1_length_size(inner_sequence_len) + 1;
    let mut out = BytesMut::with_capacity(total_len);
    out.put_u8(CONSTRUCTED_SEQUENCE_TAG);
    encode_asn1_length(inner_sequence_len, &mut out);
    for int_buffer in int_buffers.iter() {
        out.put_u8(INTEGER_TAG);
        encode_asn1_length(int_buffer.len(), &mut out);
        out.put_slice(int_buffer);
    }
    Bytes::from(out)
}

/// Encode the ASN.1 DER prefix length
fn encode_asn1_length(n: usize, buff: &mut BytesMut) {
    if n < 128 {
        buff.put_u8(n as u8);
    }
    else {
        const LENGTH_TAG: u8 = 0x80;
        let num_len_bytes = (asn1_length_size(n) - 1) as u8;
        buff.put_u8(num_len_bytes | LENGTH_TAG);
        for i in (0..num_len_bytes).rev() {
            buff.put_u8((n >> (8 * i)) as u8);
        }
    }
}

/// Get the buffer size needed to encode the asn1 length
fn asn1_length_size(n: usize) -> usize {
    if n < 128 {
        1
    }
    else {
        1 + mem::size_of::<usize>() - (n.leading_zeros() as usize / 8)
    }
}

// Convert an unsigned big-endian integer to a signed one
fn int_be_from_unsigned_to_signed(i: &[u8]) -> Vec<u8> {
    BigInt::from_bytes_be(Sign::Plus, i).to_signed_bytes_be()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;
    use std::str;

    static DISCOVERY_DOCUMENT: &'static str = "{\"issuer\":\"http://identity\",\"jwks_uri\":\"http://identity/.well-known/openid-configuration/jwks\",\"authorization_endpoint\":\"http://identity/connect/authorize\",\"token_endpoint\":\"http://identity/connect/token\",\"userinfo_endpoint\":\"http://identity/connect/userinfo\",\"end_session_endpoint\":\"http://identity/connect/endsession\",\"check_session_iframe\":\"http://identity/connect/checksession\",\"revocation_endpoint\":\"http://identity/connect/revocation\",\"introspection_endpoint\":\"http://identity/connect/introspect\",\"frontchannel_logout_supported\":true,\"frontchannel_logout_session_supported\":true,\"backchannel_logout_supported\":true,\"backchannel_logout_session_supported\":true,\"scopes_supported\":[\"openid\",\"profile\",\"api1\",\"offline_access\"],\"claims_supported\":[\"sub\",\"name\",\"family_name\",\"given_name\",\"middle_name\",\"nickname\",\"preferred_username\",\"profile\",\"picture\",\"website\",\"gender\",\"birthdate\",\"zoneinfo\",\"locale\",\"updated_at\"],\"grant_types_supported\":[\"authorization_code\",\"client_credentials\",\"refresh_token\",\"implicit\",\"password\"],\"response_types_supported\":[\"code\",\"token\",\"id_token\",\"id_token token\",\"code id_token\",\"code token\",\"code id_token token\"],\"response_modes_supported\":[\"form_post\",\"query\",\"fragment\"],\"token_endpoint_auth_methods_supported\":[\"client_secret_basic\",\"client_secret_post\"],\"subject_types_supported\":[\"public\"],\"id_token_signing_alg_values_supported\":[\"RS256\"],\"code_challenge_methods_supported\":[\"plain\",\"S256\"]}";
    static JWKS_DOCUMENT: &'static str = "{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"kid\":\"5A2FC6E95AECCD7D11A45F885FBEA9252B1851F5\",\"x5t\":\"Wi_G6VrszX0RpF-IX76pJSsYUfU\",\"e\":\"AQAB\",\"n\":\"viuRydGmSbij9PpVMEZdy29J0Ae_M883JTORRfcsKvEM1T0gdYIyX23vq86vSkmlQVOiiK--5U9HgmNm0lMojQC2KC7Gtkfh1uD7AQxDo1TBRT0BqxcBxrzyJ308AT5aiLnFVYlf4f0fvdIJZ-KAyXvAQAXLN3PwksFcYAVavGy402MzLNaqWAZ2iQ0-MD0mLfgCZItjkVbX5hvOZ9q2ZlRsw33bLttEguord12BY025yzBiZOGOZVZxEw8Ngz3gs4J23wxXpeeMUDvArPRi7se8Jev26_E8I0J77ttiuScbVDqX-lDYShsKGTDWxUcpVeqBvSk6GL-gxbPdogIokQ\",\"x5c\":[\"MIIDEjCCAfqgAwIBAgIQHkrDz62eL6FHq0bfB3HyvzANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFEaW1lbnNpb25JZGVudGl0eTAeFw0xODA3MDUxNDIyMTNaFw0yODA3MDUxNDMyMTNaMBwxGjAYBgNVBAMMEURpbWVuc2lvbklkZW50aXR5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAviuRydGmSbij9PpVMEZdy29J0Ae/M883JTORRfcsKvEM1T0gdYIyX23vq86vSkmlQVOiiK++5U9HgmNm0lMojQC2KC7Gtkfh1uD7AQxDo1TBRT0BqxcBxrzyJ308AT5aiLnFVYlf4f0fvdIJZ+KAyXvAQAXLN3PwksFcYAVavGy402MzLNaqWAZ2iQ0+MD0mLfgCZItjkVbX5hvOZ9q2ZlRsw33bLttEguord12BY025yzBiZOGOZVZxEw8Ngz3gs4J23wxXpeeMUDvArPRi7se8Jev26/E8I0J77ttiuScbVDqX+lDYShsKGTDWxUcpVeqBvSk6GL+gxbPdogIokQIDAQABo1AwTjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBRq5Pqhyrrps7bwnKXudCWkBxDNZDANBgkqhkiG9w0BAQsFAAOCAQEAXdTP+pWN+T0sR1ktsSXKo0WflqYMbjV88gQYjdFF2S97W7Tbl/1NvH89II7QyPSspwgRmXtPul6DUXkzRroEv6ZHUGEBGok1Ep+xFsA8Ajs+WIdKULglf//nojsKYAvqdul3eM6Gke8HQTuvz2eQbhUQwMz9+Wu987S4UwVaxAb2hDJUVwLD9WuBHn46FvDyaxpkP/cdlR4CG8WD1B9AkcxjD/uNX19TpUuDmU6wX784OqU2maydNzvjET1k3pX472mt6jL1uLa4XokyvFELpsvUgtopiVN2h+DZruHu5pyGQCfozAJEFcFeYmX6hX78bF61wfdFMP1rsSLCYwtS+Q==\"],\"alg\":\"RS256\"}]}";
    static KEY: &'static str = "MIIBCgKCAQEAviuRydGmSbij9PpVMEZdy29J0Ae/M883JTORRfcsKvEM1T0gdYIyX23vq86vSkmlQVOiiK++5U9HgmNm0lMojQC2KC7Gtkfh1uD7AQxDo1TBRT0BqxcBxrzyJ308AT5aiLnFVYlf4f0fvdIJZ+KAyXvAQAXLN3PwksFcYAVavGy402MzLNaqWAZ2iQ0+MD0mLfgCZItjkVbX5hvOZ9q2ZlRsw33bLttEguord12BY025yzBiZOGOZVZxEw8Ngz3gs4J23wxXpeeMUDvArPRi7se8Jev26/E8I0J77ttiuScbVDqX+lDYShsKGTDWxUcpVeqBvSk6GL+gxbPdogIokQIDAQAB";

    #[test]
    fn test_discovery() {
        let discovery = parse_discovery(&Bytes::from(DISCOVERY_DOCUMENT));
        assert!(discovery.is_ok());
        let discovery_unwrapped = discovery.unwrap();
        assert_eq!(discovery_unwrapped.jwks_uri, "http://identity/.well-known/openid-configuration/jwks");
        assert_eq!(discovery_unwrapped.issuer, "http://identity");
    }

    #[test]
    fn test_web_keyset() {
        let jwks = decode_web_keyset(&Bytes::from(JWKS_DOCUMENT));
        assert!(jwks.is_ok());
        let keys = jwks.unwrap();
        
        assert_eq!(keys[&WrappedAlgorithm(Algorithm::RS256)].len(), 1);
        assert!(keys[&WrappedAlgorithm(Algorithm::RS256)].contains_key("5A2FC6E95AECCD7D11A45F885FBEA9252B1851F5"));
        assert_eq!(keys[&WrappedAlgorithm(Algorithm::RS256)]["5A2FC6E95AECCD7D11A45F885FBEA9252B1851F5"], base64::decode(KEY).unwrap());
    }
}