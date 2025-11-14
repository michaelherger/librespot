#[allow(unused)]
use log::{error, info, warn};

use serde_json::{Value, json};
use std::fs;
use std::process::exit;

use librespot::core::authentication::Credentials;
use librespot::core::session::Session;
use librespot::core::spotify_uri::SpotifyUri;

use librespot::playback::audio_backend;
use librespot::playback::config::{AudioFormat, PlayerConfig};
use librespot::playback::mixer::NoOpVolume;
use librespot::playback::player::Player;

#[cfg(debug_assertions)]
const DEBUGMODE: bool = true;
#[cfg(not(debug_assertions))]
const DEBUGMODE: bool = false;

pub const VERSION: &str = "2.1.0";

pub fn check(version_info: String) {
    println!("ok {}", version_info);

    let capabilities = json!({
        "autoplay": true,
        "debug": DEBUGMODE,
        "lms-auth": true,
        "no-ap-port": true,
        "oauth": true,
        "podcasts": true,
        "save-token": true,
        "temp-dir": true,
        "version": VERSION,
        "volume-normalisation": true,
        "zeroconf-port": true
    });

    #[cfg(feature = "passthrough-decoder")]
    if let Value::Object(map) = &mut capabilities {
        map.insert("ogg-direct".to_string(), json!(true));
    }

    println!("{}", capabilities);
    exit(0);
}

// inspired by examples/get_token.rs
pub async fn get_token(
    _client_id: Option<String>,
    save_token: Option<String>,
    last_credentials: Option<Credentials>,
    session: Session,
) {
    match last_credentials {
        Some(last_credentials) => match session.connect(last_credentials, true).await {
            Ok(()) => match session.login5().auth_token().await {
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
        },
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

            let track = SpotifyUri::from_uri(
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
