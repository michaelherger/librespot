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

use librespot_core::authentication::Credentials;
use librespot_core::session::Session;
use librespot_core::spotify_uri::SpotifyUri;

use librespot_playback::audio_backend;
use librespot_playback::config::{AudioFormat, PlayerConfig};
use librespot_playback::mixer::NoOpVolume;
use librespot_playback::player::Player;

#[cfg(debug_assertions)]
const DEBUGMODE: bool = true;
#[cfg(not(debug_assertions))]
const DEBUGMODE: bool = false;

pub const VERSION: &str = "2.2.0";

pub fn check(version_info: String) {
    println!("ok {}", version_info);

    let mut capabilities = json!({
        "autoplay": true,
        "connect-stream": true,
        "debug": DEBUGMODE,
        "http-stream": true,
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
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use bytes::Bytes;
    use futures_util::StreamExt;
    use http_body_util::{BodyExt, Full, StreamBody};
    use hyper::body::Frame;
    use hyper::server::conn::http1;
    use hyper::{Response, StatusCode};
    use hyper_util::rt::TokioIo;
    use hyper_util::server::graceful::GracefulShutdown;
    use log::{info, warn};
    use serde_json::json;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;
    use tokio::sync::{mpsc, watch};
    use tokio_stream::wrappers::ReceiverStream;

    use librespot_playback::audio_backend::{Sink, SinkError, SinkResult};
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
        /// Sender half of the watch channel used to signal the relay task to drain
        /// pre-seek PCM bytes. Incremented on every `PlayerEvent::Seeked`.
        pub flush_tx: Option<watch::Sender<u64>>,
        /// Monotonically increasing generation counter; incremented on seek.
        pub seek_gen: Arc<AtomicU64>,
    }

    impl LMS {
        pub fn new(
            host_port: Option<String>,
            player_mac: Option<String>,
            auth: Option<String>,
            flush_tx: Option<watch::Sender<u64>>,
        ) -> Self {
            Self {
                host_port,
                player_mac,
                // CR-02: sanitize `--lms-auth` credential to prevent CRLF injection
                // into the hand-rolled HTTP/1.0 notify request. `trim()` removes
                // leading/trailing whitespace; `replace` strips any embedded CR/LF
                // that would let an attacker inject arbitrary request headers.
                auth: auth.map(|raw| raw.trim().replace(['\r', '\n'], "").to_owned()),
                suppress_next_volume: Arc::new(AtomicBool::new(false)),
                flush_tx,
                seek_gen: Arc::new(AtomicU64::new(0)),
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
                // flush_tx is not Clone (watch::Sender doesn't implement Clone),
                // so clones do not hold a sender. Only the original LMS instance
                // (the one passed to the event dispatcher) fires flush signals.
                flush_tx: None,
                seek_gen: Arc::clone(&self.seek_gen),
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
                    let new_id = track_id.to_id().unwrap_or_default();
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
                // Also fires the watch-channel flush signal so the relay task
                // drains pre-seek PCM bytes (D-03 in-place drain variant).
                // Pitfall 5: only fire on Seeked, never on Playing (which also
                // fires on resume) to avoid draining during gapless transitions.
                PlayerEvent::Seeked { position_ms, .. } => {
                    if current_track.is_some() {
                        let secs = f64::from(*position_ms) / 1000.0;
                        self.notify("seek", &format!("{secs:.3}"), "").await;
                    }
                    // Fire flush regardless of whether a track is active: the
                    // relay must drain even if current_track is not yet set.
                    if let Some(tx) = &self.flush_tx {
                        let new_gen = self.seek_gen.fetch_add(1, Ordering::Release) + 1;
                        tx.send(new_gen).ok();
                        info!("lms-connect: seek-flush signal sent (gen={})", new_gen);
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
                    let new_id = audio_item.track_id.to_id().unwrap_or_default();
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

    // -------------------------------------------------------------------------
    // HttpStreamSink
    // -------------------------------------------------------------------------

    /// Audio sink for `--connect-stream` mode.
    ///
    /// Unlike [`ConnectNullSink`] (which discards decoded PCM), this sink sends
    /// a continuous S16LE stereo stream over an mpsc channel to the HTTP stream
    /// server, allowing LMS to consume it via `canDirectStream` as a plain HTTP
    /// audio source.
    ///
    /// Unlike `pipe.rs::StdoutSink` (which calls `exit(0)` in `stop()`), this
    /// sink's `stop()` only resets counters. The process outlives individual
    /// track boundaries so Spotify Connect can deliver gapless playback across
    /// the LMS player's lifetime.
    ///
    /// Rate-limiting follows the same nanosecond wall-clock math as
    /// [`ConnectNullSink`], using plain `std::thread::sleep` since the Player
    /// runs `Sink::write` on a dedicated OS thread (std::thread::spawn in
    /// player.rs), not on a Tokio worker. `blocking_send` is therefore safe
    /// here (BIN-03).
    pub struct HttpStreamSink {
        pcm_tx: mpsc::Sender<Bytes>,
        /// Sender half of the flush watch-channel. Held here purely for ownership
        /// (keeping the channel open); the actual flush signals are fired from
        /// `LMS::handle_player_event` on `PlayerEvent::Seeked`.
        #[allow(dead_code)]
        flush_tx: watch::Sender<u64>,
        began_at: Instant,
        frames_consumed: u64,
    }

    impl HttpStreamSink {
        /// Constructor for use in the `--connect-stream` wiring.
        ///
        /// `pcm_tx` is the sending half of the channel that connects this sink
        /// (OS thread) to `http_stream_server` (Tokio task).
        ///
        /// `flush_tx` is held for ownership only; flush signals are sent by
        /// `LMS::handle_player_event` on `PlayerEvent::Seeked`.
        ///
        /// Panics if `format != AudioFormat::S16` — only S16LE is supported
        /// (pitfall S-03: format continuity).
        pub fn open(
            _device: Option<String>,
            format: AudioFormat,
            pcm_tx: mpsc::Sender<Bytes>,
            flush_tx: watch::Sender<u64>,
        ) -> Box<dyn Sink> {
            if format != AudioFormat::S16 {
                panic!(
                    "HttpStreamSink: only AudioFormat::S16 supported, got {:?}",
                    format
                );
            }
            Box::new(Self {
                pcm_tx,
                flush_tx,
                began_at: Instant::now(),
                frames_consumed: 0,
            })
        }
    }

    impl Sink for HttpStreamSink {
        fn start(&mut self) -> SinkResult<()> {
            // Reset the wall-clock anchor every time playback begins so the
            // rate-limiter doesn't drift across pause/resume cycles.
            self.began_at = Instant::now();
            self.frames_consumed = 0;
            Ok(())
        }

        fn stop(&mut self) -> SinkResult<()> {
            // CRITICAL: do NOT exit() the process here. The pipe/StdoutSink
            // backend in librespot terminates the daemon at end-of-stream under
            // #[cfg(feature = "spotty")]; that is designed for --single-track.
            // HttpStreamSink must survive track boundaries for gapless Connect
            // playback (BIN-03). No stdout flush needed — we write to an mpsc
            // channel, not stdout.
            self.frames_consumed = 0;
            self.began_at = Instant::now();
            Ok(())
        }

        fn write(&mut self, packet: AudioPacket, converter: &mut Converter) -> SinkResult<()> {
            let AudioPacket::Samples(samples) = packet else {
                // Raw passthrough variant — not in scope for this sink; skip.
                return Ok(());
            };

            // Convert f64 samples to S16LE and reinterpret as a byte slice.
            // SAFETY: i16 has alignment 2 and size 2; the resulting byte slice
            // has len = samples_s16.len() * 2 and points to valid memory for
            // the lifetime of `samples_s16`. This is equivalent to zerocopy's
            // IntoBytes::as_bytes() but avoids adding zerocopy as a dependency
            // to the spotty binary crate (zerocopy lives in the playback crate).
            let samples_s16 = converter.f64_to_s16(&samples);
            // SAFETY: `i16` values are valid to view as two `u8` bytes; pointer
            // and length are derived from the valid Vec allocation.
            let bytes: &[u8] = unsafe {
                std::slice::from_raw_parts(
                    samples_s16.as_ptr().cast::<u8>(),
                    samples_s16.len() * std::mem::size_of::<i16>(),
                )
            };

            // Rate-limiter — identical to ConnectNullSink (pitfall S-01).
            // Without this sleep the decoder races ahead of wall-clock time,
            // making Spotify clients show nonsensical seek positions.
            let frames_in_packet = (samples.len() / NUM_CHANNELS as usize) as u64;
            self.frames_consumed = self.frames_consumed.saturating_add(frames_in_packet);
            let expected_ns: u128 =
                u128::from(self.frames_consumed) * 1_000_000_000u128 / u128::from(SAMPLE_RATE);
            let elapsed_ns: u128 = self.began_at.elapsed().as_nanos();

            if expected_ns > elapsed_ns {
                let park_ns = (expected_ns - elapsed_ns) as u64;
                std::thread::sleep(Duration::from_nanos(park_ns));
            }

            // Send PCM bytes over the channel to the HTTP stream server.
            // Player::new spawns a std::thread but runs block_on() with its
            // own tokio Runtime inside it (player.rs:517), so Sink::write
            // executes within a tokio context. blocking_send would panic.
            // Use try_send with a spin-retry: the channel has 256 slots
            // (~1.5s of audio) and a single consumer, so contention is
            // transient — the rate-limiter above already paces us to
            // real-time, keeping the channel nearly empty.
            let chunk = Bytes::copy_from_slice(bytes);
            loop {
                match self.pcm_tx.try_send(chunk.clone()) {
                    Ok(()) => break,
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        return Err(SinkError::OnWrite(
                            "HTTP stream server shut down".into(),
                        ));
                    }
                }
            }

            Ok(())
        }
    }

    // -------------------------------------------------------------------------
    // http_stream_server
    // -------------------------------------------------------------------------

    /// HTTP server that streams PCM audio to LMS via a single persistent
    /// GET /stream endpoint.
    ///
    /// Listens on the supplied `listener` (bound to 127.0.0.1 before calling
    /// this function). Receives decoded S16LE PCM from [`HttpStreamSink`] via
    /// `pcm_rx`. Uses a relay-per-connection pattern so the single
    /// `mpsc::Receiver` is shared across sequential connections without cloning.
    ///
    /// ## Connection lifecycle
    ///
    /// 1. Accept incoming TCP connection.
    /// 2. If `spirc_active` is false → return 503 with `Retry-After: 2`. Close.
    /// 3. Otherwise:
    ///    a. Drain stale PCM chunks from `pcm_rx` via `try_recv` (D-03).
    ///    b. Spawn a relay task that forwards from `pcm_rx` to a per-connection
    ///       bounded channel (`conn_tx` / `conn_rx`).
    ///    c. Serve a 200 response with `Content-Type: audio/L16;rate=44100;channels=2`
    ///       and a streaming body backed by `ReceiverStream(conn_rx)`.
    ///    d. When LMS disconnects, `conn_tx.send` in the relay fails → relay
    ///       exits → the Mutex over `pcm_rx` is released for the next connection.
    ///
    /// ## Shutdown
    ///
    /// When `shutdown_rx` fires, the accept loop breaks and
    /// `graceful.shutdown().await` drains in-flight connections.
    pub async fn http_stream_server(
        listener: tokio::net::TcpListener,
        pcm_rx: mpsc::Receiver<Bytes>,
        spirc_active: Arc<AtomicBool>,
        shutdown_rx: tokio::sync::oneshot::Receiver<()>,
        flush_rx: watch::Receiver<u64>,
    ) {
        use std::sync::Mutex;

        let server = http1::Builder::new();
        let graceful = GracefulShutdown::new();
        let mut shutdown_rx = std::pin::pin!(shutdown_rx);

        // Wrap pcm_rx in Arc<Mutex> so the relay task can acquire it
        // exclusively without requiring pcm_rx: Clone (it isn't).
        let pcm_rx = Arc::new(Mutex::new(pcm_rx));

        // Wrap flush_rx in Arc<Mutex> so it can be shared across connections.
        let flush_rx = Arc::new(Mutex::new(flush_rx));

        // CR-01: guard against concurrent relay tasks that would split the PCM
        // stream across two competing connections. When a relay is already active
        // a second HTTP connection gets 503 with Retry-After: 1 and should retry
        // once the first relay exits and clears this flag.
        let relay_active = Arc::new(AtomicBool::new(false));

        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    let (stream, _addr) = match accept_result {
                        Ok(pair) => pair,
                        Err(e) => {
                            warn!("http_stream_server: accept error: {e}");
                            continue;
                        }
                    };

                    let spirc_active = Arc::clone(&spirc_active);
                    let pcm_rx = Arc::clone(&pcm_rx);
                    let flush_rx = Arc::clone(&flush_rx);
                    let relay_active = Arc::clone(&relay_active);

                    // Build the service function for this single connection.
                    // Both response paths (503 and 200-stream) are erased to
                    // BoxBody<Bytes, hyper::Error> so the return type is uniform.
                    let svc = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
                        let spirc_active = Arc::clone(&spirc_active);
                        let pcm_rx = Arc::clone(&pcm_rx);
                        let flush_rx = Arc::clone(&flush_rx);
                        let relay_active = Arc::clone(&relay_active);
                        async move {
                            // WR-02: validate request method and path. Only GET /stream
                            // is served as audio; anything else gets 404/405.
                            if req.method() != hyper::Method::GET {
                                let body = Full::new(Bytes::new())
                                    .map_err(|e| match e {})
                                    .boxed();
                                let resp = Response::builder()
                                    .status(StatusCode::METHOD_NOT_ALLOWED)
                                    .header("Content-Length", "0")
                                    .body(body)
                                    .expect("BUG: static 405 response builder failed");
                                return Ok::<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error>(resp);
                            }
                            if req.uri().path() != "/stream" {
                                let body = Full::new(Bytes::new())
                                    .map_err(|e| match e {})
                                    .boxed();
                                let resp = Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .header("Content-Length", "0")
                                    .body(body)
                                    .expect("BUG: static 404 response builder failed");
                                return Ok::<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error>(resp);
                            }

                            if !spirc_active.load(Ordering::SeqCst) {
                                // Spirc not active yet — tell LMS to retry shortly.
                                let body = Full::new(Bytes::new())
                                    .map_err(|e| match e {})
                                    .boxed();
                                let resp = Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .header("Retry-After", "2")
                                    .header("Content-Length", "0")
                                    .body(body)
                                    .expect("BUG: static 503 (spirc inactive) response builder failed");
                                return Ok::<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error>(resp);
                            }

                            // CR-01: reject concurrent relay attempts — the PCM stream
                            // must flow to exactly one connection at a time. The old
                            // relay task clears the flag on exit.
                            if relay_active.swap(true, Ordering::AcqRel) {
                                let body = Full::new(Bytes::new())
                                    .map_err(|e| match e {})
                                    .boxed();
                                let resp = Response::builder()
                                    .status(StatusCode::SERVICE_UNAVAILABLE)
                                    .header("Retry-After", "1")
                                    .header("Content-Length", "0")
                                    .body(body)
                                    .expect("BUG: static 503 (relay busy) response builder failed");
                                return Ok::<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error>(resp);
                            }

                            // Drain stale pre-seek audio from the channel (D-03).
                            {
                                let mut rx = pcm_rx.lock().unwrap();
                                while rx.try_recv().is_ok() {}
                            }

                            // Per-connection relay channel (capacity 64 frames).
                            let (conn_tx, conn_rx) = mpsc::channel::<Bytes>(64);

                            // Relay task: acquires exclusive access to pcm_rx via
                            // the Mutex and forwards chunks to conn_tx. Uses
                            // recv().await (WR-01: no busy-poll) rather than
                            // try_recv/yield_now. Clears relay_active on exit so
                            // the next connection can start a new relay (CR-01).
                            //
                            // At the top of each loop iteration, checks flush_rx
                            // for a new seek generation. If one is found, drains
                            // the pcm_rx of pre-seek bytes before forwarding
                            // post-seek audio (in-place relay drain, Approach D).
                            let pcm_rx_clone = Arc::clone(&pcm_rx);
                            let flush_rx_clone = Arc::clone(&flush_rx);
                            let relay_active_clone = Arc::clone(&relay_active);
                            tokio::spawn(async move {
                                // Take exclusive ownership of the receiver for the
                                // duration of this relay. The Mutex ensures only one
                                // relay task holds the receiver at a time.
                                //
                                // Initialise last_seen_gen from the current value so
                                // we don't drain on the very first iteration.
                                let mut last_seen_gen: u64 = {
                                    let rx = flush_rx_clone.lock().unwrap();
                                    *rx.borrow()
                                };

                                loop {
                                    // --- Seek-flush drain (top of loop, before read) ---
                                    // Poll has_changed() without holding the mutex
                                    // across an await point.
                                    let flush_pending = {
                                        let rx = flush_rx_clone.lock().unwrap();
                                        rx.has_changed().unwrap_or(false)
                                    };
                                    if flush_pending {
                                        let new_gen = {
                                            let mut rx = flush_rx_clone.lock().unwrap();
                                            *rx.borrow_and_update()
                                        };
                                        if new_gen > last_seen_gen {
                                            // Drain all queued pre-seek PCM bytes.
                                            let mut count: u64 = 0;
                                            let mut rx = pcm_rx_clone.lock().unwrap();
                                            while rx.try_recv().is_ok() {
                                                count += 1;
                                            }
                                            last_seen_gen = new_gen;
                                            info!(
                                                "lms-connect: relay flushed {} pre-seek chunks (gen={})",
                                                count, new_gen
                                            );
                                        }
                                    }

                                    // --- Normal relay ---
                                    // WR-01: poll once and release the lock before
                                    // yielding to the runtime (must not hold mutex
                                    // across await point).
                                    let chunk = {
                                        let mut rx = pcm_rx_clone.lock().unwrap();
                                        rx.try_recv().ok()
                                    };
                                    match chunk {
                                        Some(bytes) => {
                                            if conn_tx.send(bytes).await.is_err() {
                                                // Client disconnected — relay done.
                                                break;
                                            }
                                        }
                                        None => {
                                            // No data available right now. Sleep
                                            // briefly (1 ms) instead of a hot
                                            // yield_now loop. At 44100 Hz / 2ch
                                            // packets arrive ~every 10 ms so 1 ms
                                            // adds negligible latency.
                                            tokio::time::sleep(
                                                std::time::Duration::from_millis(1),
                                            )
                                            .await;
                                        }
                                    }
                                }
                                // Clear the relay-active flag so the next LMS
                                // reconnect can start a fresh relay (CR-01).
                                relay_active_clone.store(false, Ordering::Release);
                            });

                            // Build streaming response body, erased to BoxBody.
                            let stream = ReceiverStream::new(conn_rx)
                                .map(|chunk| Ok::<Frame<Bytes>, hyper::Error>(Frame::data(chunk)));
                            let body = BodyExt::boxed(StreamBody::new(stream));

                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "audio/L16;rate=44100;channels=2")
                                .body(body)
                                .expect("BUG: static 200 response builder failed");

                            Ok::<Response<http_body_util::combinators::BoxBody<Bytes, hyper::Error>>, hyper::Error>(resp)
                        }
                    });

                    let io = TokioIo::new(stream);
                    let conn = server.serve_connection(io, svc);
                    let fut = graceful.watch(conn);
                    tokio::spawn(async move {
                        let _ = fut.await;
                    });
                }
                _ = &mut shutdown_rx => {
                    break;
                }
            }
        }

        graceful.shutdown().await;
    }
}
