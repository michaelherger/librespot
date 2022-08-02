use std::{
    convert::{TryFrom, TryInto},
    fmt::Debug,
    ops::Deref,
};

use crate::{
    audio::{
        file::AudioFiles,
        item::{AudioItem, AudioItemResult, InnerAudioItem},
    },
    availability::Availabilities,
    content_rating::ContentRatings,
    image::Images,
    request::RequestResult,
    restriction::Restrictions,
    util::try_from_repeated_message,
    video::VideoFiles,
    Metadata,
};

use librespot_core::{date::Date, Error, Session, SpotifyId};

use librespot_protocol as protocol;
pub use protocol::metadata::Episode_EpisodeType as EpisodeType;

#[derive(Debug, Clone)]
pub struct Episode {
    pub id: SpotifyId,
    pub name: String,
    pub duration: i32,
    pub audio: AudioFiles,
    pub description: String,
    pub number: i32,
    pub publish_time: Date,
    pub covers: Images,
    pub language: String,
    pub is_explicit: bool,
    pub show: SpotifyId,
    pub videos: VideoFiles,
    pub video_previews: VideoFiles,
    pub audio_previews: AudioFiles,
    pub restrictions: Restrictions,
    pub freeze_frames: Images,
    pub keywords: Vec<String>,
    pub allow_background_playback: bool,
    pub availability: Availabilities,
    pub external_url: String,
    pub episode_type: EpisodeType,
    pub has_music_and_talk: bool,
    pub content_rating: ContentRatings,
    pub is_audiobook_chapter: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Episodes(pub Vec<SpotifyId>);

impl Deref for Episodes {
    type Target = Vec<SpotifyId>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[async_trait]
impl InnerAudioItem for Episode {
    async fn get_audio_item(session: &Session, id: SpotifyId) -> AudioItemResult {
        let episode = Self::get(session, id).await?;
        let availability = Self::available_for_user(
            &session.user_data(),
            &episode.availability,
            &episode.restrictions,
        );

        Ok(AudioItem {
            id,
            spotify_uri: id.to_uri()?,
            files: episode.audio,
            name: episode.name,
            duration: episode.duration,
            availability,
            alternatives: None,
            is_explicit: episode.is_explicit,
        })
    }
}

#[async_trait]
impl Metadata for Episode {
    type Message = protocol::metadata::Episode;

    async fn request(session: &Session, episode_id: SpotifyId) -> RequestResult {
        session.spclient().get_episode_metadata(episode_id).await
    }

    fn parse(msg: &Self::Message, _: SpotifyId) -> Result<Self, Error> {
        Self::try_from(msg)
    }
}

impl TryFrom<&<Self as Metadata>::Message> for Episode {
    type Error = librespot_core::Error;
    fn try_from(episode: &<Self as Metadata>::Message) -> Result<Self, Self::Error> {
        Ok(Self {
            id: episode.try_into()?,
            name: episode.get_name().to_owned(),
            duration: episode.get_duration().to_owned(),
            audio: episode.get_audio().into(),
            description: episode.get_description().to_owned(),
            number: episode.get_number(),
            publish_time: episode.get_publish_time().try_into()?,
            covers: episode.get_cover_image().get_image().into(),
            language: episode.get_language().to_owned(),
            is_explicit: episode.get_explicit().to_owned(),
            show: episode.get_show().try_into()?,
            videos: episode.get_video().into(),
            video_previews: episode.get_video_preview().into(),
            audio_previews: episode.get_audio_preview().into(),
            restrictions: episode.get_restriction().into(),
            freeze_frames: episode.get_freeze_frame().get_image().into(),
            keywords: episode.get_keyword().to_vec(),
            allow_background_playback: episode.get_allow_background_playback(),
            availability: episode.get_availability().try_into()?,
            external_url: episode.get_external_url().to_owned(),
            episode_type: episode.get_field_type(),
            has_music_and_talk: episode.get_music_and_talk(),
            content_rating: episode.get_content_rating().into(),
            is_audiobook_chapter: episode.get_is_audiobook_chapter(),
        })
    }
}

try_from_repeated_message!(<Episode as Metadata>::Message, Episodes);
