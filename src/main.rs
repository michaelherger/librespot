#[macro_use]
extern crate serde_json;

use futures_util::{future, FutureExt, StreamExt};
use librespot_playback::player::PlayerEvent;
use log::{error, info, trace, warn};
use sha1::{Digest, Sha1};
use tokio::sync::mpsc::UnboundedReceiver;
use url::Url;

use librespot::connect::spirc::Spirc;
use librespot::core::authentication::Credentials;
use librespot::core::cache::Cache;
use librespot::core::config::{ConnectConfig, DeviceType, SessionConfig};
use librespot::core::session::Session;
use librespot::core::version;
use librespot::playback::audio_backend::{self, SinkBuilder};
use librespot::playback::config::{
    AudioFormat, Bitrate, NormalisationMethod, NormalisationType, PlayerConfig, VolumeCtrl,
};
use librespot::playback::mixer::softmixer::SoftMixer;
use librespot::playback::mixer::{self, MixerConfig, MixerFn};
use librespot::playback::player::Player;

mod spotty;
use spotty::LMS;

use std::env;
use std::ops::RangeInclusive;
use std::path::Path;
use std::pin::Pin;
use std::process::exit;
use std::str::FromStr;
use std::time::Duration;
use std::time::Instant;

const VERSION: &'static str = concat!(env!("CARGO_PKG_NAME"), " v", env!("CARGO_PKG_VERSION"));

#[cfg(target_os = "windows")]
const NULLDEVICE: &'static str = "NUL";
#[cfg(not(target_os = "windows"))]
const NULLDEVICE: &'static str = "/dev/null";

fn device_id(name: &str) -> String {
    hex::encode(Sha1::digest(name.as_bytes()))
}

fn usage(program: &str, opts: &getopts::Options) -> String {
    let repo_home = env!("CARGO_PKG_REPOSITORY");
    let desc = env!("CARGO_PKG_DESCRIPTION");
    let version = get_version_string();
    let brief = format!(
        "{}\n\n{}\n\n{}\n\nUsage: {} [<Options>]",
        version, desc, repo_home, program
    );
    opts.usage(&brief)
}

#[cfg(debug_assertions)]
fn setup_logging(quiet: bool, verbose: bool) {
    let mut builder = env_logger::Builder::new();
    match env::var("RUST_LOG") {
        Ok(config) => {
            builder.parse_filters(&config);
            builder.init();

            if verbose {
                warn!("`--verbose` flag overidden by `RUST_LOG` environment variable");
            } else if quiet {
                warn!("`--quiet` flag overidden by `RUST_LOG` environment variable");
            }
        }
        Err(_) => {
            if verbose {
                builder.parse_filters("libmdns=info,librespot=trace,spotty=trace");
            } else if quiet {
                builder.parse_filters("libmdns=warn,librespot=warn,spotty=warn");
            } else {
                builder.parse_filters("libmdns=info,librespot=info,spotty=info");
            }
            builder.init();

            if verbose && quiet {
                warn!("`--verbose` and `--quiet` are mutually exclusive. Logging can not be both verbose and quiet. Using verbose mode.");
            }
        }
    }
}

fn get_version_string() -> String {
    #[cfg(debug_assertions)]
    const BUILD_PROFILE: &str = "debug";
    #[cfg(not(debug_assertions))]
    const BUILD_PROFILE: &str = "release";

    format!(
        "{spottyvers} - using librespot {semver} {sha} (Built on {build_date}, Build ID: {build_id}, Profile: {build_profile})",
        spottyvers = VERSION,
        semver = version::SEMVER,
        sha = version::SHA_SHORT,
        build_date = version::BUILD_DATE,
        build_id = version::BUILD_ID,
        build_profile = BUILD_PROFILE
    )
}

struct Setup {
    format: AudioFormat,
    backend: SinkBuilder,
    mixer: MixerFn,
    cache: Option<Cache>,
    player_config: PlayerConfig,
    session_config: SessionConfig,
    connect_config: ConnectConfig,
    mixer_config: MixerConfig,
    credentials: Option<Credentials>,
    enable_discovery: bool,
    zeroconf_port: u16,

    // spotty
    authenticate: bool,
    single_track: Option<String>,
    start_position: u32,
    client_id: Option<String>,
    scopes: Option<String>,
    get_token: bool,
    save_token: Option<String>,
    lms: LMS,
}

fn get_setup() -> Setup {
    const VALID_INITIAL_VOLUME_RANGE: RangeInclusive<u16> = 0..=100;
    const AP_PORT: &str = "ap-port";
    const AUTHENTICATE: &str = "authenticate";
    const AUTOPLAY: &str = "autoplay";
    const BITRATE: &str = "bitrate";
    const CACHE: &str = "cache";
    const CHECK: &str = "check";
    const CLIENT_ID: &str = "client-id";
    const DISABLE_AUDIO_CACHE: &str = "disable-audio-cache";
    const DISABLE_DISCOVERY: &str = "disable-discovery";
    const DISABLE_GAPLESS: &str = "disable-gapless";
    const ENABLE_AUDIO_CACHE: &str = "enable-audio-cache";
    const ENABLE_VOLUME_NORMALISATION: &str = "enable-volume-normalisation";
    const GET_TOKEN: &str = "get-token";
    const HELP: &str = "help";
    const INITIAL_VOLUME: &str = "initial-volume";
    const LMS_AUTH: &str = "lms-auth";
    const LOGITECH_MEDIA_SERVER: &str = "lms";
    const NAME: &str = "name";
    const NORMALISATION_GAIN_TYPE: &str = "normalisation-gain-type";
    const PASSTHROUGH: &str = "passthrough";
    const PASS_THROUGH: &str = "pass-through";
    const PASSWORD: &str = "password";
    const PLAYER_MAC: &str = "player-mac";
    const PROXY: &str = "proxy";
    const SAVE_TOKEN: &str = "save-token";
    const SCOPE: &str = "scope";
    const SINGLE_TRACK: &str = "single-track";
    const START_POSITION: &str = "start-position";
    const QUIET: &str = "quiet";
    const USERNAME: &str = "username";
    const VERBOSE: &str = "verbose";
    const VERSION: &str = "version";
    const ZEROCONF_PORT: &str = "zeroconf-port";

    // Mostly arbitrary.
    const AUTHENTICATE_SHORT: &str = "a";
    const AUTOPLAY_SHORT: &str = "A";
    const AP_PORT_SHORT: &str = "";
    const BITRATE_SHORT: &str = "b";
    const CACHE_SHORT: &str = "c";
    const DISABLE_AUDIO_CACHE_SHORT: &str = "G";
    const ENABLE_AUDIO_CACHE_SHORT: &str = "";
    const DISABLE_GAPLESS_SHORT: &str = "g";
    const HELP_SHORT: &str = "h";
    const CLIENT_ID_SHORT: &str = "i";
    const ENABLE_VOLUME_NORMALISATION_SHORT: &str = "N";
    const NAME_SHORT: &str = "n";
    const DISABLE_DISCOVERY_SHORT: &str = "O";
    const PASSTHROUGH_SHORT: &str = "P";
    const PASSWORD_SHORT: &str = "p";
    const QUIET_SHORT: &str = "q";
    const INITIAL_VOLUME_SHORT: &str = "R";
    const GET_TOKEN_SHORT: &str = "t";
    const SAVE_TOKEN_SHORT: &str = "T";
    const USERNAME_SHORT: &str = "u";
    const VERSION_SHORT: &str = "V";
    const VERBOSE_SHORT: &str = "v";
    const NORMALISATION_GAIN_TYPE_SHORT: &str = "W";
    const CHECK_SHORT: &str = "x";
    const PROXY_SHORT: &str = "";
    const ZEROCONF_PORT_SHORT: &str = "z";

    // Options that have different desc's
    // depending on what backends were enabled at build time.
    const INITIAL_VOLUME_DESC: &str = "Initial volume in % from 0 - 100. Defaults to 50.";

    let mut opts = getopts::Options::new();
    opts.optflag(
        HELP_SHORT,
        HELP,
        "Print this help menu.",
    )
    .optflag(
        VERSION_SHORT,
        VERSION,
        "Display librespot version string.",
    )
    .optflag(
        VERBOSE_SHORT,
        VERBOSE,
        "Enable verbose log output.",
    )
    .optflag(
        QUIET_SHORT,
        QUIET,
        "Only log warning and error messages.",
    )
    .optflag(
        DISABLE_AUDIO_CACHE_SHORT,
        DISABLE_AUDIO_CACHE,
        "(Only here fore compatibility with librespot - audio cache is disabled by default).",
    )
    .optflag(
        ENABLE_AUDIO_CACHE_SHORT,
        ENABLE_AUDIO_CACHE,
        "Enable caching of the audio data."
    )
    .optflag(
        DISABLE_DISCOVERY_SHORT,
        DISABLE_DISCOVERY,
        "Disable zeroconf discovery mode.",
    )
    .optflag(
        DISABLE_GAPLESS_SHORT,
        DISABLE_GAPLESS,
        "Disable gapless playback.",
    )
    .optflag(
        AUTOPLAY_SHORT,
        AUTOPLAY,
        "Automatically play similar songs when your music ends.",
    )
    .optflag(
        PASSTHROUGH_SHORT,
        PASSTHROUGH,
        "Pass a raw stream to the output. Only works with the pipe and subprocess backends.",
    )
    .optflag(
        ENABLE_VOLUME_NORMALISATION_SHORT,
        ENABLE_VOLUME_NORMALISATION,
        "Play all tracks at approximately the same apparent volume.",
    )
    .optopt(
        NAME_SHORT,
        NAME,
        "Device name. Defaults to Spotty.",
        "NAME",
    )
    .optopt(
        BITRATE_SHORT,
        BITRATE,
        "Bitrate (kbps) {96|160|320}. Defaults to 160.",
        "BITRATE",
    )
    .optopt(
        CACHE_SHORT,
        CACHE,
        "Path to a directory where files will be cached.",
        "PATH",
    )
    .optopt(
        USERNAME_SHORT,
        USERNAME,
        "Username used to sign in with.",
        "USERNAME",
    )
    .optopt(
        PASSWORD_SHORT,
        PASSWORD,
        "Password used to sign in with.",
        "PASSWORD",
    )
    .optopt(
        INITIAL_VOLUME_SHORT,
        INITIAL_VOLUME,
        INITIAL_VOLUME_DESC,
        "VOLUME",
    )
    .optopt(
        NORMALISATION_GAIN_TYPE_SHORT,
        NORMALISATION_GAIN_TYPE,
        "Specify the normalisation gain type to use {track|album|auto}. Defaults to auto.",
        "TYPE",
    )
    .optopt(
        ZEROCONF_PORT_SHORT,
        ZEROCONF_PORT,
        "The port the internal server advertises over zeroconf 1 - 65535. Ports <= 1024 may require root privileges.",
        "PORT",
    )
    .optopt(
        PROXY_SHORT,
        PROXY,
        "HTTP proxy to use when connecting.",
        "URL",
    )
    .optopt(
        AP_PORT_SHORT,
        AP_PORT,
        "Connect to an AP with a specified port 1 - 65535. If no AP with that port is present a fallback AP will be used. Available ports are usually 80, 443 and 4070.",
        "PORT",
    )
    // spotty
    .optflag(
        AUTHENTICATE_SHORT,
        AUTHENTICATE,
        "Authenticate given username and password. Make sure you define a cache folder to store credentials."
    )
    .optopt(
        "",
        SINGLE_TRACK,
        "Play a single track ID and exit.",
        "ID"
    )
    .optopt(
        "",
        START_POSITION,
        "Position (in seconds) where playback should be started. Only valid with the --single-track option.",
        "STARTPOSITION"
    )
    .optflag(
        CHECK_SHORT,
        CHECK,
        "Run quick internal check"
    )
    .optopt(
        CLIENT_ID_SHORT,
        CLIENT_ID,
        "A Spotify client_id to be used to get the oauth token. Required with the --get-token request.",
        "CLIENT_ID"
    )
    .optopt(
        "",
        SCOPE,
        "The scopes you want to have access to with the oauth token.",
        "SCOPE"
    )
    .optflag(
        GET_TOKEN_SHORT,
        GET_TOKEN,
        "Get oauth token to be used with the web API etc. and print it to the console."
    )
    .optopt(
        SAVE_TOKEN_SHORT,
        SAVE_TOKEN,
        "Get oauth token to be used with the web API etc. and store it in the given file.",
        "TOKENFILE"
    )
    .optflag(
        "",
        PASS_THROUGH,
        "Pass raw stream to output, only works for \"pipe\"."
    )
    .optopt(
        "",
        LOGITECH_MEDIA_SERVER,
        "hostname and port of Logitech Media Server instance (eg. localhost:9000)",
        "LMS"
    )
    .optopt(
        "",
        LMS_AUTH,
        "Authentication data to access Logitech Media Server",
        "LMSAUTH"
    )
    .optopt(
        "",
        PLAYER_MAC,
        "MAC address of the Squeezebox to be controlled",
        "MAC"
    );

    let args: Vec<_> = std::env::args_os()
        .filter_map(|s| match s.into_string() {
            Ok(valid) => Some(valid),
            Err(s) => {
                eprintln!(
                    "Command line argument was not valid Unicode and will not be evaluated: {:?}",
                    s
                );
                None
            }
        })
        .collect();

    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Error parsing command line options: {}", e);
            println!("\n{}", usage(&args[0], &opts));
            exit(1);
        }
    };

    let stripped_env_key = |k: &str| {
        k.trim_start_matches("LIBRESPOT_")
            .replace('_', "-")
            .to_lowercase()
    };

    let env_vars: Vec<_> = env::vars_os().filter_map(|(k, v)| match k.into_string() {
        Ok(key) if key.starts_with("LIBRESPOT_") => {
            let stripped_key = stripped_env_key(&key);
            // We only care about long option/flag names.
            if stripped_key.chars().count() > 1 && matches.opt_defined(&stripped_key) {
                match v.into_string() {
                    Ok(value) => Some((key, value)),
                    Err(s) => {
                        eprintln!("Environment variable was not valid Unicode and will not be evaluated: {}={:?}", key, s);
                        None
                    }
                }
            } else {
                None
            }
        },
        _ => None
    })
    .collect();

    let opt_present =
        |opt| matches.opt_present(opt) || env_vars.iter().any(|(k, _)| stripped_env_key(k) == opt);

    let opt_str = |opt| {
        if matches.opt_present(opt) {
            matches.opt_str(opt)
        } else {
            env_vars
                .iter()
                .find(|(k, _)| stripped_env_key(k) == opt)
                .map(|(_, v)| v.to_string())
        }
    };

    if opt_present(HELP) {
        println!("{}", usage(&args[0], &opts));
        exit(0);
    }

    if opt_present(VERSION) {
        println!("{}", get_version_string());
        exit(0);
    }

    if opt_present(CHECK) {
        spotty::check(get_version_string());
    }

    #[cfg(debug_assertions)]
    setup_logging(opt_present(QUIET), opt_present(VERBOSE));

    info!("{}", get_version_string());

    if !env_vars.is_empty() {
        trace!("Environment variable(s):");

        for (k, v) in &env_vars {
            if matches!(k.as_str(), "LIBRESPOT_PASSWORD" | "LIBRESPOT_USERNAME") {
                trace!("\t\t{}=\"XXXXXXXX\"", k);
            } else if v.is_empty() {
                trace!("\t\t{}=", k);
            } else {
                trace!("\t\t{}=\"{}\"", k, v);
            }
        }
    }

    let args_len = args.len();

    if args_len > 1 {
        trace!("Command line argument(s):");

        for (index, key) in args.iter().enumerate() {
            let opt = key.trim_start_matches('-');

            if index > 0
                && key.starts_with('-')
                && &args[index - 1] != key
                && matches.opt_defined(opt)
                && matches.opt_present(opt)
            {
                if matches!(opt, PASSWORD | PASSWORD_SHORT | USERNAME | USERNAME_SHORT) {
                    // Don't log creds.
                    trace!("\t\t{} \"XXXXXXXX\"", key);
                } else {
                    let value = matches.opt_str(opt).unwrap_or_else(|| "".to_string());
                    if value.is_empty() {
                        trace!("\t\t{}", key);
                    } else {
                        trace!("\t\t{} \"{}\"", key, value);
                    }
                }
            }
        }
    }

    let invalid_error_msg =
        |long: &str, short: &str, invalid: &str, valid_values: &str, default_value: &str| {
            error!("Invalid `--{}` / `-{}`: \"{}\"", long, short, invalid);

            if !valid_values.is_empty() {
                println!("Valid `--{}` / `-{}` values: {}", long, short, valid_values);
            }

            if !default_value.is_empty() {
                println!("Default: {}", default_value);
            }
        };

    let empty_string_error_msg = |long: &str, short: &str| {
        error!("`--{}` / `-{}` can not be an empty string", long, short);
        exit(1);
    };

    let mixer = mixer::find(Some(SoftMixer::NAME).as_deref()).expect("Invalid mixer");
    let mixer_type: Option<String> = None;

    let mixer_config = {
        let mixer_default_config = MixerConfig::default();

        let device = mixer_default_config.device;

        let index = mixer_default_config.index;

        let control = mixer_default_config.control;

        let volume_ctrl = VolumeCtrl::Linear;

        MixerConfig {
            device,
            control,
            index,
            volume_ctrl,
        }
    };

    let cache = {
        let volume_dir = opt_str(CACHE).map(|p| p.into());

        let cred_dir = volume_dir.clone();

        let audio_dir = if opt_present(DISABLE_AUDIO_CACHE) {
            None
        } else {
            opt_str(CACHE)
                .as_ref()
                .map(|p| AsRef::<Path>::as_ref(p).join("files"))
        };

        let limit = None;

        match Cache::new(cred_dir, volume_dir, audio_dir, limit) {
            Ok(cache) => Some(cache),
            Err(e) => {
                warn!("Cannot create cache: {}", e);
                None
            }
        }
    };

    let credentials = {
        let cached_creds = cache.as_ref().and_then(Cache::credentials);

        if let Some(username) = opt_str(USERNAME) {
            if username.is_empty() {
                empty_string_error_msg(USERNAME, USERNAME_SHORT);
            }
            if let Some(password) = opt_str(PASSWORD) {
                if password.is_empty() {
                    empty_string_error_msg(PASSWORD, PASSWORD_SHORT);
                }
                Some(Credentials::with_password(username, password))
            } else {
                match cached_creds {
                    Some(creds) if username == creds.username => Some(creds),
                    _ => {
                        let prompt = &format!("Password for {}: ", username);
                        match rpassword::prompt_password_stderr(prompt) {
                            Ok(password) => {
                                if !password.is_empty() {
                                    Some(Credentials::with_password(username, password))
                                } else {
                                    trace!("Password was empty.");
                                    if cached_creds.is_some() {
                                        trace!("Using cached credentials.");
                                    }
                                    cached_creds
                                }
                            }
                            Err(e) => {
                                warn!("Cannot parse password: {}", e);
                                if cached_creds.is_some() {
                                    trace!("Using cached credentials.");
                                }
                                cached_creds
                            }
                        }
                    }
                }
            }
        } else {
            if cached_creds.is_some() {
                trace!("Using cached credentials.");
            }
            cached_creds
        }
    };

    // don't enable discovery while fetching tracks or tokens
    let enable_discovery = !opt_present(DISABLE_DISCOVERY)
        && !opt_present(SINGLE_TRACK)
        && !opt_present(SAVE_TOKEN)
        && !opt_present(GET_TOKEN);

    if credentials.is_none() && !enable_discovery {
        error!("Credentials are required if discovery is disabled.");
        exit(1);
    }

    if !enable_discovery && opt_present(ZEROCONF_PORT) {
        warn!(
            "With the `--{}` / `-{}` flag set `--{}` / `-{}` has no effect.",
            DISABLE_DISCOVERY, DISABLE_DISCOVERY_SHORT, ZEROCONF_PORT, ZEROCONF_PORT_SHORT
        );
    }

    let zeroconf_port = if enable_discovery {
        opt_str(ZEROCONF_PORT)
            .map(|port| match port.parse::<u16>() {
                Ok(value) if value != 0 => value,
                _ => {
                    let valid_values = &format!("1 - {}", u16::MAX);
                    invalid_error_msg(ZEROCONF_PORT, ZEROCONF_PORT_SHORT, &port, valid_values, "");

                    exit(1);
                }
            })
            .unwrap_or(0)
    } else {
        0
    };

    let connect_config = {
        let connect_default_config = ConnectConfig::default();

        let name = opt_str(NAME).unwrap_or_else(|| connect_default_config.name.clone());

        if name.is_empty() {
            empty_string_error_msg(NAME, NAME_SHORT);
            exit(1);
        }

        let initial_volume = opt_str(INITIAL_VOLUME)
            .map(|initial_volume| {
                let volume = match initial_volume.parse::<u16>() {
                    Ok(value) if (VALID_INITIAL_VOLUME_RANGE).contains(&value) => value,
                    _ => {
                        let valid_values = &format!(
                            "{} - {}",
                            VALID_INITIAL_VOLUME_RANGE.start(),
                            VALID_INITIAL_VOLUME_RANGE.end()
                        );

                        let default_value = &connect_default_config
                            .initial_volume
                            .unwrap_or_default()
                            .to_string();

                        invalid_error_msg(
                            INITIAL_VOLUME,
                            INITIAL_VOLUME_SHORT,
                            &initial_volume,
                            valid_values,
                            default_value,
                        );

                        exit(1);
                    }
                };

                (volume as f32 / 100.0 * VolumeCtrl::MAX_VOLUME as f32) as u16
            })
            .or_else(|| match mixer_type.as_deref() {
                _ => cache.as_ref().and_then(Cache::volume),
            });

        let device_type = DeviceType::default();
        let has_volume_ctrl = !matches!(mixer_config.volume_ctrl, VolumeCtrl::Fixed);
        let autoplay = opt_present(AUTOPLAY);

        ConnectConfig {
            name,
            device_type,
            initial_volume,
            has_volume_ctrl,
            autoplay,
        }
    };

    let session_config = SessionConfig {
        user_agent: version::VERSION_STRING.to_string(),
        device_id: device_id(&connect_config.name),
        proxy: opt_str(PROXY).or_else(|| std::env::var("http_proxy").ok()).map(
            |s| {
                match Url::parse(&s) {
                    Ok(url) => {
                        if url.host().is_none() || url.port_or_known_default().is_none() {
                            error!("Invalid proxy url, only URLs on the format \"http://host:port\" are allowed");
                            exit(1);
                        }

                        if url.scheme() != "http" {
                            error!("Only unsecure http:// proxies are supported");
                            exit(1);
                        }

                        url
                    },
                    Err(e) => {
                        error!("Invalid proxy URL: \"{}\", only URLs in the format \"http://host:port\" are allowed", e);
                        exit(1);
                    }
                }
            },
        ),
        ap_port: opt_str(AP_PORT).map(|port| match port.parse::<u16>() {
            Ok(value) if value != 0 => value,
            _ => {
                let valid_values = &format!("1 - {}", u16::MAX);
                invalid_error_msg(AP_PORT, AP_PORT_SHORT, &port, valid_values, "");

                exit(1);
            }
        }),
    };

    let player_config = {
        let player_default_config = PlayerConfig::default();

        let bitrate = opt_str(BITRATE)
            .as_deref()
            .map(|bitrate| {
                Bitrate::from_str(bitrate).unwrap_or_else(|_| {
                    invalid_error_msg(BITRATE, BITRATE_SHORT, bitrate, "96, 160, 320", "160");
                    exit(1);
                })
            })
            .unwrap_or(player_default_config.bitrate);

        let gapless = !opt_present(DISABLE_GAPLESS);

        let normalisation = opt_present(ENABLE_VOLUME_NORMALISATION);

        let normalisation_type;

        if !normalisation {
            for a in &[NORMALISATION_GAIN_TYPE] {
                if opt_present(a) {
                    warn!(
                        "Without the `--{}` / `-{}` flag normalisation options have no effect.",
                        ENABLE_VOLUME_NORMALISATION, ENABLE_VOLUME_NORMALISATION_SHORT,
                    );
                    break;
                }
            }

            normalisation_type = player_default_config.normalisation_type;
        } else {
            normalisation_type = opt_str(NORMALISATION_GAIN_TYPE)
                .as_deref()
                .map(|gain_type| {
                    NormalisationType::from_str(gain_type).unwrap_or_else(|_| {
                        invalid_error_msg(
                            NORMALISATION_GAIN_TYPE,
                            NORMALISATION_GAIN_TYPE_SHORT,
                            gain_type,
                            "track, album, auto",
                            &format!("{:?}", player_default_config.normalisation_type),
                        );

                        exit(1);
                    })
                })
                .unwrap_or(player_default_config.normalisation_type);
        }

        let ditherer = PlayerConfig::default().ditherer;
        let passthrough = opt_present(PASSTHROUGH) || opt_present(PASS_THROUGH);

        PlayerConfig {
            bitrate,
            gapless,
            passthrough,
            normalisation,
            normalisation_type,
            normalisation_method: NormalisationMethod::Basic,
            normalisation_pregain_db: player_default_config.normalisation_pregain_db,
            normalisation_threshold_dbfs: player_default_config.normalisation_threshold_dbfs,
            normalisation_attack_cf: player_default_config.normalisation_attack_cf,
            normalisation_release_cf: player_default_config.normalisation_release_cf,
            normalisation_knee_db: player_default_config.normalisation_knee_db,
            ditherer,
            lms_connect_mode: !opt_present(SINGLE_TRACK),
        }
    };

    let authenticate = opt_present(AUTHENTICATE);
    let start_position = opt_str(START_POSITION)
        .unwrap_or("0".to_string())
        .parse::<f32>()
        .unwrap_or(0.0);

    let save_token = opt_str(SAVE_TOKEN).unwrap_or("".to_string());
    let client_id = opt_str(CLIENT_ID).unwrap_or(format!("{}", include_str!("client_id.txt")));

    let lms = LMS::new(
        opt_str(LOGITECH_MEDIA_SERVER),
        opt_str(PLAYER_MAC),
        opt_str(LMS_AUTH),
    );

    Setup {
        format: AudioFormat::default(),
        backend: audio_backend::find(None).unwrap(),
        mixer,
        cache,
        player_config,
        session_config,
        connect_config,
        mixer_config,
        credentials,
        enable_discovery,
        zeroconf_port,
        // spotty
        authenticate,
        single_track: opt_str(SINGLE_TRACK),
        start_position: (start_position * 1000.0) as u32,
        get_token: opt_present(GET_TOKEN) || save_token.as_str().len() != 0,
        save_token: if save_token.as_str().len() == 0 {
            None
        } else {
            Some(save_token)
        },
        client_id: if client_id.as_str().len() == 0 {
            None
        } else {
            Some(client_id)
        },
        scopes: opt_str(SCOPE),
        lms,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    const RUST_BACKTRACE: &str = "RUST_BACKTRACE";
    const RECONNECT_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(600);
    const RECONNECT_RATE_LIMIT: usize = 5;

    if env::var(RUST_BACKTRACE).is_err() {
        env::set_var(RUST_BACKTRACE, "full")
    }

    let setup = get_setup();

    let mut last_credentials = None;
    let mut spirc: Option<Spirc> = None;
    let mut spirc_task: Option<Pin<_>> = None;
    let mut player_event_channel: Option<UnboundedReceiver<PlayerEvent>> = None;
    let mut auto_connect_times: Vec<Instant> = vec![];
    let mut discovery = None;
    let mut connecting: Pin<Box<dyn future::FusedFuture<Output = _>>> = Box::pin(future::pending());

    if setup.enable_discovery {
        let device_id = setup.session_config.device_id.clone();
        match librespot::discovery::Discovery::builder(device_id)
            .name(setup.connect_config.name.clone())
            .device_type(setup.connect_config.device_type)
            .port(setup.zeroconf_port)
            .launch()
        {
            Ok(d) => discovery = Some(d),
            Err(err) => warn!("Could not initialise discovery: {}.", err),
        };
    }

    if let Some(credentials) = setup.credentials {
        last_credentials = Some(credentials.clone());
        connecting = Box::pin(
            Session::connect(
                setup.session_config.clone(),
                credentials,
                setup.cache.clone(),
                true,
            )
            .fuse(),
        );
    } else if discovery.is_none() {
        error!(
            "Discovery is unavailable and no credentials provided. Authentication is not possible."
        );
        exit(1);
    }

    if let Some(ref track_id) = setup.single_track {
        spotty::play_track(
            track_id.to_string(),
            setup.start_position,
            last_credentials,
            setup.player_config,
            setup.session_config,
        )
        .await;
        exit(0);
    } else if setup.get_token {
        spotty::get_token(
            setup.client_id,
            setup.scopes,
            setup.save_token,
            last_credentials,
            setup.session_config,
        )
        .await;
        exit(0);
    }

    loop {
        tokio::select! {
            credentials = async {
                match discovery.as_mut() {
                    Some(d) => d.next().await,
                    _ => None
                }
            }, if discovery.is_some() => {
                match credentials {
                    Some(credentials) => {
                        last_credentials = Some(credentials.clone());
                        auto_connect_times.clear();

                        if let Some(spirc) = spirc.take() {
                            spirc.shutdown();
                        }
                        if let Some(spirc_task) = spirc_task.take() {
                            // Continue shutdown in its own task
                            tokio::spawn(spirc_task);
                        }

                        connecting = Box::pin(Session::connect(
                            setup.session_config.clone(),
                            credentials,
                            setup.cache.clone(),
                            true,
                        ).fuse());
                    },
                    None => {
                        error!("Discovery stopped unexpectedly");
                        exit(1);
                    }
                }
            },
            session = &mut connecting, if !connecting.is_terminated() => match session {
                Ok((session,_)) => {
                    // Spotty auth mode: exit after saving credentials
                    if setup.authenticate {
                        println!("authorized");
                        break;
                    }

                    let mixer_config = setup.mixer_config.clone();
                    let mixer = (setup.mixer)(mixer_config);
                    let player_config = setup.player_config.clone();
                    let connect_config = setup.connect_config.clone();

                    let soft_volume = mixer.get_soft_volume();
                    let format = setup.format;
                    let backend = setup.backend;
                    let device = Some(NULLDEVICE.to_string());
                    let (player, event_channel) =
                        Player::new(player_config, session.clone(), soft_volume, move || {
                            (backend)(device, format)
                        });

                    let (spirc_, spirc_task_) = Spirc::new(connect_config, session, player, mixer);

                    spirc = Some(spirc_);
                    spirc_task = Some(Box::pin(spirc_task_));
                    player_event_channel = Some(event_channel);
                },
                Err(e) => {
                    error!("Connection failed: {}", e);
                    exit(1);
                }
            },
            _ = async {
                if let Some(task) = spirc_task.as_mut() {
                    task.await;
                }
            }, if spirc_task.is_some() => {
                spirc_task = None;

                warn!("Spirc shut down unexpectedly");

                let mut reconnect_exceeds_rate_limit = || {
                    auto_connect_times.retain(|&t| t.elapsed() < RECONNECT_RATE_LIMIT_WINDOW);
                    auto_connect_times.len() > RECONNECT_RATE_LIMIT
                };

                match last_credentials.clone() {
                    Some(credentials) if !reconnect_exceeds_rate_limit() => {
                        auto_connect_times.push(Instant::now());

                        connecting = Box::pin(Session::connect(
                            setup.session_config.clone(),
                            credentials,
                            setup.cache.clone(),
                            true
                        ).fuse());
                    },
                    _ => {
                        error!("Spirc shut down too often. Not reconnecting automatically.");
                        exit(1);
                    },
                }
            },
            event = async {
                match player_event_channel.as_mut() {
                    Some(p) => p.recv().await,
                    _ => None
                }
            }, if player_event_channel.is_some() => match event {
                Some(event) => {
                    setup.lms.signal_event(event).await;
                },
                None => {
                    player_event_channel = None;
                }
            },
            _ = tokio::signal::ctrl_c() => {
                break;
            },
            else => break,
        }
    }

    info!("Gracefully shutting down");

    // Shutdown spirc if necessary
    if let Some(spirc) = spirc {
        spirc.shutdown();

        if let Some(mut spirc_task) = spirc_task {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => (),
                _ = spirc_task.as_mut() => (),
                else => (),
            }
        }
    }
}
