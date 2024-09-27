#[allow(unused)]
use log::{error, info, warn};

use serde_json::{json, Value};
use std::fs;
use std::process::exit;

use librespot::core::authentication::Credentials;
use librespot::core::session::Session;
use librespot::core::spotify_id::SpotifyId;

use librespot::playback::audio_backend;
use librespot::playback::config::{AudioFormat, PlayerConfig};
use librespot::playback::mixer::NoOpVolume;
use librespot::playback::player::Player;

const SCOPES: &str = "user-read-private,playlist-read-private,playlist-read-collaborative,playlist-modify-public,playlist-modify-private,user-follow-modify,user-follow-read,user-library-read,user-library-modify,user-top-read,user-read-recently-played";

#[cfg(debug_assertions)]
const DEBUGMODE: bool = true;
#[cfg(not(debug_assertions))]
const DEBUGMODE: bool = false;

pub fn check(version_info: String) {
    println!("ok {}", version_info);

    let capabilities = json!({
        "autoplay": true,
        "debug": DEBUGMODE,
        "lms-auth": true,
        "no-ap-port": true,
        "ogg-direct": true,
        "podcasts": true,
        "save-token": true,
        "temp-dir": true,
        "version": env!("CARGO_PKG_VERSION").to_string(),
        "volume-normalisation": true,
        "zeroconf-port": true
    });

    println!("{}", capabilities);
    exit(0);
}

// inspired by examples/get_token.rs
pub async fn get_token(
    client_id: Option<String>,
    scopes: Option<String>,
    save_token: Option<String>,
    last_credentials: Option<Credentials>,
    session: Session,
) {
    match last_credentials {
        Some(last_credentials) => {
            if let Some(client_id) = client_id {
                let scopes = scopes.unwrap_or_else(|| SCOPES.to_string());
                session.set_client_id(client_id.as_str());

                match session.connect(last_credentials, true).await {
                    Ok(()) => match session.token_provider().get_token(&scopes).await {
                        Ok(token) => {
                            write_response(
                                json!({
                                    "accessToken": token.access_token,
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
                    },
                    Err(error) => {
                        error!("Failed to create session (get_token): {:?}", error);
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
        fs::write(&save_token, json_token.to_string()).expect("Can't write token file");
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
    session: Session,
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

            if let Err(error) = session.connect(last_credentials, false).await {
                error!("Failed to create session (play_track): {:?}", error);
                return;
            }

            match track {
                Ok(track) => {
                    let player =
                        Player::new(player_config, session, Box::new(NoOpVolume), move || {
                            backend(None, audio_format)
                        });

                    player.load(track, true, start_position);
                    player.await_end_of_track().await;
                }
                Err(error) => {
                    error!("Failed to get track: {:?}", error);
                }
            };
        }
        None => {
            println!("Missing credentials");
        }
    }
}
