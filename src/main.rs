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
 
mod openid;
mod token;

use actix_web::{client, error, middleware, server, App, AsyncResponder, Body, Error, HttpMessage, HttpRequest, HttpResponse, Responder};
use bytes::Bytes;
use futures::{Future, Stream, future};
use jsonwebtoken::{Algorithm, Validation};
use std::time::{Duration, Instant};
use serde::Deserialize;
use log::info;
use std::{cmp, hash, str, sync, collections, fmt};
use config::{FileFormat, ConfigError};
#[cfg(feature = "tls")]
use native_tls::{TlsAcceptor, Identity};
#[cfg(feature = "tls")]
use std::io::Read;
#[cfg(not(feature = "tls"))]
use log::error;
use crate::error::{ErrorForbidden, ErrorInternalServerError};
use crate::client::ClientRequest;
use crate::collections::HashMap;
use crate::sync::{Arc, RwLock};
use crate::future::Either;
use crate::token::{WrappedAlgorithm, validate_token, get_token_str, has_missing_kid};
use crate::openid::openid_connect_retrieve;

/// The state of the proxy
struct ProxyState {
    discovery_url: String,
    upstream_url: String,
    key_expiry: Option<Duration>,
    upstream_timeout: Duration,
    validation_info: Arc<RwLock<ValidationInfo>>
}

/// The information/keys necessary to validate tokens, is shared among worker threads
struct ValidationInfo {
    client_secret: Option<Bytes>,
    validation: Validation,
    keys: HashMap<WrappedAlgorithm, HashMap<String, Bytes>>, // Map from algorithm to key-id (kid) to the encryption key
    last_key_refresh: Option<Instant>
}

#[derive(Deserialize, Debug)]
/// Configuration for the actix server
struct ServerConfig {
    listen_url: String,
    listen_ssl_url: Option<String>,
    num_workers: Option<usize>,
    cert_file: Option<String>,
    cert_password: Option<String>
}

#[derive(Deserialize, Debug)]
/// Configuration for the app state
struct AppConfig {
    provider_url: String,
    upstream_url: String,
    key_expiry_secs: Option<u64>,
    upstream_timeout_secs: Option<u64>
}

#[derive(Deserialize, Debug)]
/// Configuration for the validation of tokens
struct ValidationConfig {
    audience: Option<String>,
    client_secret: Option<String>,
    subject: Option<String>,
    leeway: Option<i64>
}

fn main() {
    env_logger::init();

    let config: ServerConfig = get_config().expect("unable to parse ServerConfig");

    let sys = actix::System::new("ooproxy");

    let validation_state = get_proxy_validation_state();

    let mut server = server::new(move || get_server_app(validation_state.clone()));
    server = server.workers(config.num_workers.unwrap_or(2));
    server = server.bind(config.listen_url).expect("unable to bind to listen address");

    if let (Some(listen_ssl_url), Some(cert_file)) = (config.listen_ssl_url, config.cert_file)  {
        #[cfg(feature = "tls")]
        {
            let ssl_acceptor = get_ssl_acceptor(&cert_file, config.cert_password.as_ref().map(String::as_ref).unwrap_or(""));

            server = server.bind_tls(listen_ssl_url, ssl_acceptor)
                           .expect("unable to bind to listen ssl address");
        }
        #[cfg(not(feature = "tls"))]
        error!("tls is not supported in this build but options listen_ssl_url ({}) and cert_file ({}) are configured, please use a build with the 'tls' feature", listen_ssl_url, cert_file);
    }

    server.start();

    info!("OOProxy - Copyright (C) 2018 HAL24000 B.V.");
    let _ = sys.run();
}

#[cfg(feature = "tls")]
/// Get an ssl acceptor, that can handle TLS for the server application
fn get_ssl_acceptor(cert_file: &str, cert_password: &str) -> TlsAcceptor {
    let mut file = std::fs::File::open(cert_file).expect("unable to open certificate file");
    let mut contents = vec![];
    file.read_to_end(&mut contents).expect("unable to read certificate file");
    let pkcs12 = Identity::from_pkcs12(&contents, cert_password).expect("certificate file has invalid format, needs a valid pfx file");
    TlsAcceptor::builder(pkcs12).build().expect("unable to build tls")
}

/// Get the server app and the initial server state
fn get_server_app(validation_info: Arc<RwLock<ValidationInfo>>) -> App<ProxyState> {
    let config: AppConfig = get_config().expect("unable to parse AppConfig");

    let proxy_state = ProxyState {
        discovery_url: config.provider_url + "/.well-known/openid-configuration",
        upstream_url: config.upstream_url,
        key_expiry: config.key_expiry_secs.map(Duration::from_secs),
        upstream_timeout: Duration::from_secs(config.upstream_timeout_secs.unwrap_or(3600)),
        validation_info: validation_info
    };

    App::with_state(proxy_state)
        .middleware(middleware::Logger::default())
        .default_resource(|r| r.f(handle_request))
}

/// Get the initial validation state for the server app
fn get_proxy_validation_state() -> Arc<RwLock<ValidationInfo>> {
    let config: ValidationConfig = get_config().expect("unable to parse ValidationConfig");

    Arc::new(RwLock::new(ValidationInfo {
        validation: Validation {
            sub: config.subject,
            aud: config.audience.map(|a| serde_json::from_str(&a).expect("unable to parse the audience configuration as json")),
            leeway: config.leeway.unwrap_or(0),
            ..Default::default()
        },
        keys: HashMap::<WrappedAlgorithm, HashMap<String, Bytes>>::new(),
        last_key_refresh: None,
        client_secret: config.client_secret.map(Bytes::from)
    }))
}

/// Retrieve data from the configuration file and/or environment variables
fn get_config<'t, TConfig>() -> Result<TConfig, ConfigError> where TConfig: Deserialize<'t>, TConfig: fmt::Debug {
    let mut config = config::Config::default();
    config.merge(config::File::new("settings.toml", FileFormat::Toml).required(false))?
          .merge(config::Environment::new())?;

    let result = config.try_into();

    info!("reading configuration: {:?}", result);

    result
}

/// Handle a http request:
/// * Sync the validation info if necessary
/// * Authenticate the token
/// * If everything succeeds, stream-proxy the request
fn handle_request(req: &HttpRequest<ProxyState>) -> impl Responder {
    let upstream_request = get_upstream_request(req);
    let token_str = get_token_str_from_request(req);
    let validation_info = &req.state().validation_info;
    let validation_info_sync = validation_info.clone();
    let validation_info_decrypt = validation_info.clone();

    sync_validation_info(&req.state().discovery_url, validation_info_sync, req.state().key_expiry, &token_str)
        .and_then(move |_| token_str)
        .and_then(move |token_str| {
            let state = validation_info_decrypt.read().expect("rw lock was poisoned due to earlier panic");
            validate_token(&token_str, &state.client_secret, &state.keys, &state.validation)
        })
        .and_then(move |_| stream_response(upstream_request))
        .responder()
}

/// Synchronize the validation information if necessary
fn sync_validation_info(discovery_url: &str, validation_info: Arc<RwLock<ValidationInfo>>, key_expiry: Option<Duration>, token_str: &Result<String, Error>) -> impl Future<Item = (), Error = Error> {
    let now = Instant::now();

    if needs_to_sync_validation_info(&validation_info, key_expiry, now, token_str) {
        info!("retrieving latest signing keys through openid");
        Either::A(
            openid_connect_retrieve(discovery_url)
                .and_then(move |openid_info| {
                    let mut state = validation_info.write().expect("rw lock was poisoned due to earlier panic");
                    state.validation.iss = Some(openid_info.issuer);
                    state.validation.algorithms = openid_info.keys.keys().map(|alg| alg.0).collect();
                    if state.client_secret.is_some() {
                        state.validation.algorithms.extend([Algorithm::HS256, Algorithm::HS384, Algorithm::HS512].iter());
                    }
                    state.keys = openid_info.keys;
                    state.last_key_refresh = Some(now);
                    info!("successfully retrieved latest signing keys through openid");
                    Ok(())
                })
        )
    }
    else {
        Either::B(futures::done(Ok(())))
    }
}

/// Check if we need to synchronize the validation information (expiry or missing key-id)
fn needs_to_sync_validation_info(validation_info: &Arc<RwLock<ValidationInfo>>, key_expiry: Option<Duration>, now: Instant, token_str: &Result<String, Error>) -> bool {
    let crypto = validation_info.read().expect("rw lock was poisoned due to earlier panic");
    let is_expired = match (crypto.last_key_refresh, key_expiry) {
        (Some(last_refresh), Some(expiry)) => now.duration_since(last_refresh) > expiry,
        (None, _) => true,
        _ => false
    };
    let has_missing_kid = token_str.as_ref()
                                   .map(|token| has_missing_kid(token, &crypto.keys))
                                   .unwrap_or(false);
    is_expired || has_missing_kid
}

/// Construct the upstream request, stream the body, copy the header/status, change the url to the upstream one
fn get_upstream_request(req: &HttpRequest<ProxyState>) -> Result<ClientRequest, Error> {
    let upstream_url = format!(
        "{}{}",
        req.state().upstream_url,
        req.uri()
           .path_and_query()
           .map(|pq| pq.as_str())
           .unwrap_or("")
    );

    info!("upstream request: {}", upstream_url);

    let body_stream = Body::Streaming(Box::new(req.payload().from_err()));

    client::ClientRequest::build_from(req)
                          .uri(upstream_url)
                          .timeout(req.state().upstream_timeout)
                          .body(body_stream)
}

/// Stream the upstream response to the client
fn stream_response(req: Result<ClientRequest, Error>) -> impl Future<Item = HttpResponse, Error = Error> {
    futures::done(req)
        .and_then(|req| req.send().map_err(Error::from))
        .and_then(|resp| {
            Ok(HttpResponse::build(resp.status())
                .body(Body::Streaming(Box::new(resp.payload().from_err()))))
        })
}

/// Retrieve the token from the authorization header
fn get_token_str_from_request(req: &HttpRequest<ProxyState>) -> Result<String, Error> {
    let header = req.headers().get("Authorization").ok_or_else(|| ErrorForbidden("authorization header not found"))?;
    let header_str = header.to_str().map_err(|_| ErrorInternalServerError("invalid characters in header"))?;
    get_token_str(header_str)
}