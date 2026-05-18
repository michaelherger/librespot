//! Spotty helper module.
//!
//! This file contains two distinct sections:
//!
//! 1. **Herger's Spotty functions** (`check`, `get_token`, `write_response`, `play_track`) —
//!    used for the standalone streaming/token helpers. These are compiled when the `spotty`
//!    Cargo feature is active (the default).
//!
//! 2. **LMS-Connect glue layer** (gated behind `#[cfg(feature = "lms-connect")]`) —
//!    the JSON-RPC notification bridge that forwards librespot's `PlayerEvent` stream
//!    into Lyrion Music Server's `spottyconnect` CLI command, plus a real-time-rate-limited
//!    null audio sink for headless Connect-receiver mode.
//!
//! ## LMS-Connect architecture
//!
//! - [`lms_connect::LMS`] holds the wiring (LMS host, target player MAC, optional
//!   HTTP-Basic auth) and the `suppress_next_volume` flag used to swallow the spurious
//!   `VolumeChanged` Spotify pushes immediately after a `SessionConnected`.
//! - [`lms_connect::ConnectNullSink`] implements the playback `Sink` trait; it discards
//!   decoded PCM frames but pseudo-rate-limits the call site so Spirc reports realistic
//!   playback positions back to the Spotify cloud.
//! - [`lms_connect::LMS::handle_player_event`] consumes a `PlayerEvent` and emits a
//!   `spottyconnect <cmd> <param1> <param2>` JSON-RPC dispatch into LMS.
//!
//! ## Wire vocabulary (the Phase-8 Perl handler must match)
//!
//! Five commands are emitted: `start`, `change`, `stop`, `volume`, `seek`.
//! `pause` is *not* emitted — the dispatcher collapses Paused and Stopped
//! variants into a single `stop` event, mirroring the contract that the
//! original hansherlighed-era plugin already speaks.
//!
//! ## Authorship of LMS-Connect section
//!
//! Written from scratch against librespot-org HEAD's `PlayerEvent` API.
//! The hansherlighed `fcdeecc` reference was read for *contract* (struct
//! field names, event name vocabulary, suppress-next-volume semantics) but
//! no code was byte-copied — see Phase 7 plan 04 deviation D-10.

// ---------------------------------------------------------------------------
// Herger's Spotty helpers (check / get_token / write_response / play_track)
// ---------------------------------------------------------------------------

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
        "keymaster-token": true,
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

// ---------------------------------------------------------------------------
// LMS-Connect glue layer (feature = "lms-connect")
// ---------------------------------------------------------------------------

#[cfg(feature = "lms-connect")]
pub mod lms_connect {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use log::{info, warn};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use librespot_playback::audio_backend::{Sink, SinkResult};
    use librespot_playback::config::AudioFormat;
    use librespot_playback::convert::Converter;
    use librespot_playback::decoder::AudioPacket;
    use librespot_playback::player::PlayerEvent;
    use librespot_playback::{NUM_CHANNELS, SAMPLE_RATE};

    // -------------------------------------------------------------------------
    // LMS struct
    // -------------------------------------------------------------------------

    /// LMS-side notification target.
    ///
    /// `host_port` is `"<host>:<port>"` (typically `"localhost:9000"`).
    /// `player_mac` is the colon-separated MAC of the target LMS player.
    /// `auth` is an optional pre-base64-encoded `user:pass` string.
    ///
    /// `suppress_next_volume` is set the moment Spirc fires `SessionConnected`,
    /// then consumed (cleared) on the very next `VolumeChanged`. This avoids
    /// pushing Spotify's stored device volume back to LMS immediately after a
    /// transfer-to-player handshake — that initial push is a Spotify-cloud
    /// echo, not a user action, and would otherwise clobber LMS-side volume.
    pub struct LMS {
        pub host_port: Option<String>,
        pub player_mac: Option<String>,
        pub auth: Option<String>,
        pub suppress_next_volume: Arc<AtomicBool>,
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
                // Trim accidental whitespace/newlines from CLI-passed creds.
                auth: auth.map(|raw| raw.trim().to_owned()),
                suppress_next_volume: Arc::new(AtomicBool::new(false)),
            }
        }

        /// True iff both the LMS host and the player MAC have been configured.
        /// Without either, `notify` is a no-op and the dispatcher short-circuits.
        pub fn is_configured(&self) -> bool {
            self.host_port.is_some() && self.player_mac.is_some()
        }
    }

    impl Clone for LMS {
        fn clone(&self) -> Self {
            Self {
                host_port: self.host_port.clone(),
                player_mac: self.player_mac.clone(),
                auth: self.auth.clone(),
                // Important: clone the Arc so all clones share the same flag.
                // The wiring spawns a Tokio task that takes ownership of one
                // clone; the suppression flag must remain a single shared cell.
                suppress_next_volume: Arc::clone(&self.suppress_next_volume),
            }
        }
    }

    // -------------------------------------------------------------------------
    // PlayerEvent dispatcher + JSON-RPC notifier
    // -------------------------------------------------------------------------

    impl LMS {
        /// Consume one [`PlayerEvent`] and emit zero-or-one matching
        /// `spottyconnect <cmd> <p1> <p2>` JSON-RPC dispatches.
        ///
        /// `current_track` is the dispatch loop's persistent cursor: the base62
        /// id of whatever track we last saw `Playing`. It is mutated in place.
        ///
        /// The five emitted command names — `start`, `change`, `stop`,
        /// `volume`, `seek` — are the wire vocabulary the Spotty-Plugin's
        /// `Connect::_connectEvent` Perl handler will match in Phase 8.
        /// `pause` is intentionally *not* emitted; Paused and Stopped both
        /// collapse into a single `stop` event (per existing plugin contract).
        pub async fn handle_player_event(
            &self,
            event: &PlayerEvent,
            current_track: &mut Option<String>,
        ) {
            if !self.is_configured() {
                return;
            }

            match event {
                // Playing fires for: track-start, un-pause, post-seek, and
                // buffer-underrun re-emit. We emit `start` only on a clean
                // None -> Some transition; same-id re-emits are no-ops, and
                // a different id replaces the cursor with `change`.
                PlayerEvent::Playing { track_id, .. } => {
                    let new_id = track_id.to_id();
                    match current_track.as_deref() {
                        Some(prev) if prev == new_id.as_str() => { /* noisy re-emit */ }
                        Some(_) => {
                            let prev = current_track.replace(new_id.clone()).unwrap_or_default();
                            self.notify("change", &new_id, &prev).await;
                        }
                        None => {
                            *current_track = Some(new_id.clone());
                            self.notify("start", &new_id, "").await;
                        }
                    }
                }

                // Both Paused and Stopped collapse into `stop`. Only fire if
                // we actually had an active track — guards against duplicate
                // stop events on idle daemon.
                PlayerEvent::Paused { .. } | PlayerEvent::Stopped { .. } => {
                    if current_track.take().is_some() {
                        self.notify("stop", "", "").await;
                    }
                }

                // VolumeChanged: librespot reports 0..=65535; LMS speaks
                // 0..=100. The first event after SessionConnected is a
                // Spotify-cloud echo, not a user action — see suppress flag.
                PlayerEvent::VolumeChanged { volume } => {
                    if self.suppress_next_volume.swap(false, Ordering::Relaxed) {
                        info!(
                            "lms-connect: suppressed activation-time volume push from Spotify (raw={})",
                            volume
                        );
                        return;
                    }
                    let pct = u32::from(*volume) * 100 / 65535;
                    self.notify("volume", &pct.to_string(), "").await;
                }

                // Seeked: report position in seconds (3 decimals). Only valid
                // mid-playback — without an active track, the seek vocabulary
                // has no LMS-side referent.
                PlayerEvent::Seeked { position_ms, .. } => {
                    if current_track.is_some() {
                        let secs = f64::from(*position_ms) / 1000.0;
                        self.notify("seek", &format!("{secs:.3}"), "").await;
                    }
                }

                // Spirc just connected to Spotify. The next VolumeChanged is
                // Spotify's stored device volume being pushed back; flag it
                // for suppression so we don't clobber LMS-side volume.
                PlayerEvent::SessionConnected { .. } => {
                    self.suppress_next_volume.store(true, Ordering::Relaxed);
                }

                // TrackChanged fires when librespot loads a new track (e.g.
                // playlist jump via Spotify app). Update the cursor and emit
                // `change` so the Perl side can switch. `Playing` may follow
                // later and will be a same-id no-op.
                PlayerEvent::TrackChanged { audio_item } => {
                    let new_id = audio_item.track_id.to_id();
                    match current_track.as_deref() {
                        Some(prev) if prev == new_id.as_str() => { /* same track */ }
                        Some(_) => {
                            let prev = current_track.replace(new_id.clone()).unwrap_or_default();
                            self.notify("change", &new_id, &prev).await;
                        }
                        None => {
                            *current_track = Some(new_id.clone());
                            self.notify("start", &new_id, "").await;
                        }
                    }
                }

                // Everything else (Loading, Preloading, EndOfTrack,
                // SetQueue, PositionChanged, ...) — no LMS equivalent.
                _ => {}
            }
        }

        /// POST a `spottyconnect <cmd> <p1> <p2>` JSON-RPC slim.request to LMS.
        ///
        /// Opens a fresh TCP connection per event (no keep-alive). Errors are
        /// logged at WARN; the daemon must never panic on a transient LMS
        /// outage. If `auth` is set, an `Authorization: Basic <base64>` header
        /// is added; the value is sent verbatim (caller pre-encoded it).
        async fn notify(&self, cmd: &str, p1: &str, p2: &str) {
            let host_port = match self.host_port.as_deref() {
                Some(h) => h,
                None => return,
            };
            let player_mac = match self.player_mac.as_deref() {
                Some(m) => m,
                None => return,
            };

            // Build the variadic spottyconnect command array. Empty trailing
            // params are dropped — matches the over-the-wire shape the Perl
            // _connectEvent handler historically expects.
            let mut params: Vec<serde_json::Value> = Vec::with_capacity(4);
            params.push(json!("spottyconnect"));
            params.push(json!(cmd));
            if !p1.is_empty() {
                params.push(json!(p1));
            }
            if !p2.is_empty() {
                params.push(json!(p2));
            }
            let body = json!({
                "id": 1,
                "method": "slim.request",
                "params": [player_mac, params],
            })
            .to_string();

            let auth_header = match self.auth.as_deref() {
                Some(creds) => format!("Authorization: Basic {creds}\r\n"),
                None => String::new(),
            };

            let request = format!(
                "POST /jsonrpc.js HTTP/1.0\r\n\
                 Host: {host_port}\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: {len}\r\n\
                 {auth_header}\
                 \r\n\
                 {body}",
                len = body.len(),
            );

            match TcpStream::connect(host_port).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(request.as_bytes()).await {
                        warn!("lms-connect: write_all to {host_port} failed for {cmd}: {e}");
                    }
                }
                Err(e) => {
                    warn!("lms-connect: TcpStream::connect({host_port}) failed for {cmd}: {e}");
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // ConnectNullSink
    // -------------------------------------------------------------------------

    /// Audio sink for headless Connect-receiver builds.
    ///
    /// We don't actually emit audio — LMS owns the audio path — but we still
    /// need to *consume* librespot's decoded PCM at roughly real-time pace so
    /// Spirc's playback-position reports stay believable. A naïve "drop every
    /// packet immediately" sink would let the player race ahead of wall-clock
    /// time, which makes Spotify clients (phone app, Connect API) display
    /// nonsensical seek positions.
    ///
    /// The implementation tracks how many stereo frames have been consumed
    /// since `start()` and parks the calling thread until wall-clock time has
    /// caught up to the implied PCM duration.
    pub struct ConnectNullSink {
        began_at: Instant,
        frames_consumed: u64,
    }

    impl ConnectNullSink {
        /// Constructor matching the `SinkBuilder` signature so this can be
        /// passed straight to `Player::new`.
        pub fn open(_device: Option<String>, _format: AudioFormat) -> Box<dyn Sink> {
            Box::new(Self {
                began_at: Instant::now(),
                frames_consumed: 0,
            })
        }
    }

    impl Sink for ConnectNullSink {
        fn start(&mut self) -> SinkResult<()> {
            // Reset the wall-clock anchor every time playback begins so the
            // rate-limiter doesn't drift across pause/resume cycles.
            self.began_at = Instant::now();
            self.frames_consumed = 0;
            Ok(())
        }

        fn stop(&mut self) -> SinkResult<()> {
            // CRITICAL: do NOT exit() the process here. The pipe/StdoutSink
            // backend in librespot terminates the daemon at end-of-stream;
            // a Connect-receiver must outlive individual track stops to
            // handle pause/resume and track changes.
            self.frames_consumed = 0;
            Ok(())
        }

        fn write(&mut self, packet: AudioPacket, _converter: &mut Converter) -> SinkResult<()> {
            let AudioPacket::Samples(samples) = packet else {
                // Raw passthrough variant — not in scope for this sink; just
                // accept and discard. Spirc still progresses its position.
                return Ok(());
            };

            let frames_in_packet = (samples.len() / NUM_CHANNELS as usize) as u64;
            self.frames_consumed = self.frames_consumed.saturating_add(frames_in_packet);

            // expected_ns = frames_consumed * 1e9 / SAMPLE_RATE
            // u128 prevents overflow at multi-hour playback durations.
            let expected_ns: u128 =
                u128::from(self.frames_consumed) * 1_000_000_000u128 / u128::from(SAMPLE_RATE);
            let elapsed_ns: u128 = self.began_at.elapsed().as_nanos();

            if expected_ns > elapsed_ns {
                let park_ns = (expected_ns - elapsed_ns) as u64;
                std::thread::sleep(Duration::from_nanos(park_ns));
            }
            Ok(())
        }
    }
}
