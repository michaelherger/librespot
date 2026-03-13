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

// LMS (Lyrion Music Server) Spotify Connect integration

use librespot::playback::audio_backend::{Sink, SinkResult};
use librespot::playback::convert::Converter;
use librespot::playback::decoder::AudioPacket;
use librespot::playback::player::PlayerEvent;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Rate-limited null sink for Spotify Connect daemon mode.
///
/// Discards decoded audio while sleeping between writes to maintain accurate
/// real-time playback position (needed so Spirc reports correct state to Spotify).
/// Unlike the pipe/StdoutSink, this sink does NOT call exit() on stop(), allowing
/// the Connect daemon to handle track transitions and pause/resume cleanly.
pub struct ConnectNullSink {
    start: Instant,
    frames: u64,
}

impl ConnectNullSink {
    pub fn open(_device: Option<String>, _format: AudioFormat) -> Box<dyn Sink> {
        Box::new(Self {
            start: Instant::now(),
            frames: 0,
        })
    }
}

impl Sink for ConnectNullSink {
    fn start(&mut self) -> SinkResult<()> {
        self.start = Instant::now();
        self.frames = 0;
        Ok(())
    }

    fn write(&mut self, packet: AudioPacket, _: &mut Converter) -> SinkResult<()> {
        if let AudioPacket::Samples(samples) = packet {
            // samples is stereo-interleaved f64; each pair is one frame
            self.frames += (samples.len() / librespot::playback::NUM_CHANNELS as usize) as u64;
            let expected_ns = self.frames * 1_000_000_000 / librespot::playback::SAMPLE_RATE as u64;
            let elapsed_ns = self.start.elapsed().as_nanos() as u64;
            if expected_ns > elapsed_ns {
                std::thread::sleep(std::time::Duration::from_nanos(expected_ns - elapsed_ns));
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct LMS {
    host_port: Option<String>,
    player_mac: Option<String>,
    auth: Option<String>,
    /// Set to true when Spirc activates the session; the very next VolumeChanged
    /// event is Spotify's stored device volume being pushed back to us, not a
    /// user-driven change. We suppress it to avoid clobbering the LMS player's
    /// current volume.
    suppress_next_volume: Arc<AtomicBool>,
}

impl LMS {
    pub fn new(
        host_port: Option<String>,
        player_mac: Option<String>,
        auth: Option<String>,
    ) -> Self {
        Self {
            host_port,
            player_mac,
            auth: auth.map(|a| a.trim().to_string()),
            suppress_next_volume: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_configured(&self) -> bool {
        self.host_port.is_some() && self.player_mac.is_some()
    }

    async fn notify(&self, cmd: &str, param1: &str, param2: &str) {
        let (host_port, player_mac) = match (&self.host_port, &self.player_mac) {
            (Some(h), Some(m)) => (h.as_str(), m.as_str()),
            _ => return,
        };

        let mut cmd_array: Vec<serde_json::Value> =
            vec![serde_json::json!("spottyconnect"), serde_json::json!(cmd)];
        if !param1.is_empty() {
            cmd_array.push(serde_json::json!(param1));
        }
        if !param2.is_empty() {
            cmd_array.push(serde_json::json!(param2));
        }

        let body = serde_json::json!({
            "id": 1,
            "method": "slim.request",
            "params": [player_mac, cmd_array],
        })
        .to_string();

        let auth_line = self
            .auth
            .as_ref()
            .map(|a| format!("Authorization: Basic {a}\r\n"))
            .unwrap_or_default();

        let request = format!(
            "POST /jsonrpc.js HTTP/1.0\r\nHost: {host_port}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\n{auth_line}\r\n{body}",
            len = body.len()
        );

        match TcpStream::connect(host_port).await {
            Ok(mut stream) => {
                if let Err(e) = stream.write_all(request.as_bytes()).await {
                    warn!("LMS notification write failed: {e}");
                }
            }
            Err(e) => {
                warn!("Failed to connect to LMS at {host_port}: {e}");
            }
        }
    }

    pub async fn handle_player_event(
        &self,
        event: &PlayerEvent,
        current_track: &mut Option<String>,
    ) {
        match event {
            PlayerEvent::Playing { track_id, .. } => {
                let id = match track_id.to_id() {
                    Ok(id) => id,
                    Err(e) => {
                        warn!("LMS: failed to get track id: {e}");
                        return;
                    }
                };
                if current_track.as_deref() == Some(id.as_str()) {
                    // Same track (e.g. seek or buffer-underrun re-emit), no action needed
                    return;
                }
                let old = current_track.replace(id.clone());
                if let Some(old_id) = old {
                    self.notify("change", &id, &old_id).await;
                } else {
                    self.notify("start", &id, "").await;
                }
            }
            PlayerEvent::Stopped { .. } | PlayerEvent::Paused { .. } => {
                if current_track.take().is_some() {
                    self.notify("stop", "", "").await;
                }
            }
            PlayerEvent::VolumeChanged { volume } => {
                // Suppress the activation-time volume push from Spotify. When
                // Spirc connects to Spotify it immediately emits the device's
                // last-remembered volume (SessionConnected fires first, setting
                // this flag). That value comes from Spotify's state, not the
                // user, and would overwrite whatever LMS had set.
                if self.suppress_next_volume.swap(false, Ordering::Relaxed) {
                    info!("LMS: suppressing activation-time volume reset from Spotify ({} -> {}%)",
                        volume, *volume as u64 * 100 / 65535);
                    return;
                }
                let pct = (*volume as u64 * 100 / 65535).to_string();
                self.notify("volume", &pct, "").await;
            }
            PlayerEvent::Seeked { position_ms, .. } => {
                // Send the exact position directly so the Perl handler can
                // seek LMS immediately without querying the REST API (which
                // frequently lags behind Spirc's WebSocket state by 500ms+).
                if current_track.is_some() {
                    let pos_secs = (*position_ms as f64 / 1000.0).to_string();
                    self.notify("seek", &pos_secs, "").await;
                }
            }
            PlayerEvent::SessionConnected { .. } => {
                // The next VolumeChanged will be Spirc pushing Spotify's stored
                // device volume; flag it for suppression.
                self.suppress_next_volume.store(true, Ordering::Relaxed);
            }
            _ => {}
        }
    }
}
