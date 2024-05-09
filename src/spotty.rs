use hyper::{Body, Client, Method, Request};
#[allow(unused)]
use log::{error, info, warn};

use serde_json::{json, Value};
use std::fs;
use std::process::exit;

use librespot::core::authentication::Credentials;
use librespot::core::config::SessionConfig;
use librespot::core::keymaster;
use librespot::core::session::Session;
use librespot::core::spotify_id::SpotifyId;
use librespot::core::cache::Cache;

use librespot::playback::audio_backend;
use librespot::playback::config::{AudioFormat, PlayerConfig};
use librespot::playback::mixer::NoOpVolume;
use librespot::playback::player::{Player, PlayerEvent};

const VERSION: &'static str = concat!(env!("CARGO_PKG_NAME"), " v", env!("CARGO_PKG_VERSION"));

const SCOPES: &str = "user-read-private,playlist-read-private,playlist-read-collaborative,playlist-modify-public,playlist-modify-private,user-follow-modify,user-follow-read,user-library-read,user-library-modify,user-top-read,user-read-recently-played";

#[cfg(debug_assertions)]
const DEBUGMODE: bool = true;
#[cfg(not(debug_assertions))]
const DEBUGMODE: bool = false;

pub fn check(version_info: String) {
    println!("ok {}", version_info.to_string());

    let capabilities = json!({
        "version": env!("CARGO_PKG_VERSION").to_string(),
        "autoplay": true,
        "lms-auth": true,
        "volume-normalisation": true,
        "debug": DEBUGMODE,
        "ogg-direct": true,
        "save-token": true,
        "podcasts": true,
        "zeroconf-port": true
    });

    println!("{}", capabilities.to_string());
    exit(0);
}

// inspired by examples/get_token.rs
pub async fn get_token(
    client_id: Option<String>,
    scopes: Option<String>,
    save_token: Option<String>,
    last_credentials: Option<Credentials>,
    session_config: SessionConfig,
) {
    match last_credentials {
        Some(last_credentials) => {
            if let Some(client_id) = client_id {
                let scopes = scopes.unwrap_or(SCOPES.to_string());

                match Session::connect(session_config, last_credentials, None, true).await {
                    Ok((session, _)) => {
                        match keymaster::get_token(&session, &client_id, &scopes).await {
                            Ok(token) => {
                                write_response(
                                    json!({
                                        "accessToken": token.access_token.to_string(),
                                        "expiresIn": token.expires_in,
                                    }),
                                    save_token,
                                );
                            }
                            Err(error) => {
                                error!("Failed to fetch token: {:?}", error);
                                write_response(
                                    json!({
                                        "error": "Failed to get access token."
                                    }),
                                    save_token,
                                );
                            }
                        }
                    }
                    Err(error) => {
                        error!("Failed to create session: {:?}", error);
                        write_response(
                            json!({
                                "error": "Failed to create session or connect to servers."
                            }),
                            save_token,
                        );
                    }
                }
            } else {
                println!("Use --client-id to provide a CLIENT_ID");
            }
        }
        None => {
            println!("Missing credentials");
        }
    }
}

fn write_response(json_token: Value, save_token: Option<String>) {
    if let Some(save_token) = save_token {
        fs::write(save_token.to_string(), json_token.to_string()).expect("Can't write token file");
    } else {
        println!("{}", json_token);
    }
}

// inspired by examples/play.rs
pub async fn play_track(
    track_id: String,
    start_position: u32,
    last_credentials: Option<Credentials>,
    player_config: PlayerConfig,
    session_config: SessionConfig,
    cache: Option<Cache>
) {
    match last_credentials {
        Some(last_credentials) => {
            let backend = audio_backend::find(None).unwrap();
            let audio_format = AudioFormat::default();

            let track = SpotifyId::from_uri(
                track_id
                    .replace("spotty://", "spotify:track:")
                    .replace("://", ":")
                    .as_str(),
            );

            match track {
                Ok(track) => match Session::connect(session_config, last_credentials, cache, true)
                    .await
                {
                    Ok((session, _)) => {
                        let (mut player, _) =
                            Player::new(player_config, session, Box::new(NoOpVolume), move || {
                                backend(None, audio_format)
                            });

                        player.load(track, true, start_position);
                        player.await_end_of_track().await;
                    }
                    Err(error) => {
                        error!("Failed to create session: {:?}", error);
                        return;
                    }
                },
                Err(error) => {
                    error!("Problem getting a Spotify ID for {}: {:?}", track_id, error);
                    return;
                }
            };
        }
        None => {
            println!("Missing credentials");
        }
    }
}

// Connect mode support

#[derive(Clone)]
pub struct LMS {
    base_url: Option<String>,
    player_mac: Option<String>,
    auth: Option<String>,
}

#[allow(unused)]
impl LMS {
    pub fn new(base_url: Option<String>, player_mac: Option<String>, auth: Option<String>) -> LMS {
        LMS {
            base_url: Some(format!(
                "http://{}/jsonrpc.js",
                base_url.unwrap_or("localhost:9000".to_string())
            )),
            player_mac: player_mac,
            auth: auth,
        }
    }

    pub fn is_configured(&self) -> bool {
        if self.base_url != None {
            if self.player_mac != None {
                return true;
            }
        }

        return false;
    }

    pub async fn signal_event(&self, event: PlayerEvent) {
        let mut command = r#"["spottyconnect","change"]"#.to_string();

        match event {
            PlayerEvent::Changed {
                old_track_id,
                new_track_id,
            } => {
                #[cfg(debug_assertions)]
                info!(
                    "event: changed, old track: {}, new track: {}",
                    old_track_id.to_base62().unwrap_or_default(),
                    new_track_id.to_base62().unwrap_or_default()
                );
                command = format!(
                    r#"["spottyconnect","change","{}","{}"]"#,
                    new_track_id.to_base62().unwrap_or_default().to_string(),
                    old_track_id.to_base62().unwrap_or_default().to_string()
                );
            }
            PlayerEvent::Started { track_id, .. } => {
                #[cfg(debug_assertions)]
                info!(
                    "event: started, track: {}",
                    track_id.to_base62().unwrap_or_default()
                );
                command = format!(
                    r#"["spottyconnect","start","{}"]"#,
                    track_id.to_base62().unwrap_or_default().to_string()
                );
            }
            PlayerEvent::Stopped { track_id, .. } => {
                #[cfg(debug_assertions)]
                info!(
                    "event: stopped, track: {}",
                    track_id.to_base62().unwrap_or_default()
                );
                command = r#"["spottyconnect","stop"]"#.to_string();
            }
            PlayerEvent::Playing {
                track_id,
                duration_ms,
                position_ms,
                ..
            } => {
                #[cfg(debug_assertions)]
                info!(
                    "event: playing, track: {}, duration: {}, position: {}",
                    track_id.to_base62().unwrap_or_default(),
                    duration_ms,
                    position_ms
                );
                // we're not implementing the seek event here, as it's going to read player state anyway
                // but signal a change if the new position has changed and is > 0
                if position_ms <= 0 {
                    return;
                }
                command = r#"["spottyconnect","change"]"#.to_string();
            }
            PlayerEvent::Paused {
                track_id,
                duration_ms,
                position_ms,
                ..
            } => {
                #[cfg(debug_assertions)]
                info!(
                    "event: paused, track: {}, duration: {}, position: {}",
                    track_id.to_base62().unwrap_or_default(),
                    duration_ms,
                    position_ms
                );
                command = r#"["spottyconnect","stop"]"#.to_string();
            }
            PlayerEvent::VolumeSet { volume } => {
                let mut new_volume = volume as u32;
                if new_volume > 0 {
                    new_volume = new_volume * 100 / u32::pow(2, 16);
                }

                if new_volume > 100 {
                    new_volume = 100;
                };

                #[cfg(debug_assertions)]
                info!("event: volume: {}", volume);
                // we're not using the volume here, as LMS will read player state anyway
                command = format!(r#"["spottyconnect","volume",{}]"#, new_volume.to_string());
            }
            _ => return,
        }

        if !self.is_configured() {
            #[cfg(debug_assertions)]
            warn!("LMS connection is not configured");
            #[cfg(debug_assertions)]
            info!("{}", command);
            return;
        }

        if let Some(ref base_url) = self.base_url {
            #[cfg(debug_assertions)]
            info!("Base URL to talk to LMS: {}", base_url);

            if let Some(ref player_mac) = self.player_mac {
                #[cfg(debug_assertions)]
                info!("Player MAC address to control: {}", player_mac);

                #[cfg(debug_assertions)]
                info!("Command to send to player: {}", command);

                let json = format!(
                    r#"{{"id": 1,"method":"slim.request","params":["{}",{}]}}"#,
                    player_mac, command
                );

                let mut auth_header = "".to_string();
                if let Some(ref auth) = self.auth {
                    auth_header = auth.trim().to_string();
                }

                let req = Request::builder()
                    .method(Method::POST)
                    .uri(base_url.to_string())
                    .header("user-agent", format!("{}", VERSION))
                    .header("content-type", "application/json")
                    .header("authorization", format!("Basic {}", auth_header))
                    .header("x-scanner", "1")
                    .body(Body::from(json.clone()))
                    .unwrap();

                let client = Client::new();
                let resp = client.request(req).await;

                match resp {
                    Ok(resp) => {
                        #[cfg(debug_assertions)]
                        info!("Response: {}", resp.status());
                    }
                    Err(error) => {
                        warn!("Problem posting to {} / {}: {:?}", base_url, json, error);
                    }
                }
            }
        }
    }
}
