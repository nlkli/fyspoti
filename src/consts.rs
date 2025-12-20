pub const SPOTIFY_VERSION: u64 = 124200290;

#[repr(u8)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum PacketType {
    SecretBlock = 2,
    Ping = 4,
    StreamChunk = 8,
    StreamChunkRes = 9,
    ChannelError = 10,
    ChannelAbort = 11,
    RequestKey = 12,
    AesKey = 13,
    AesKeyError = 14,

    Image = 25,
    CountryCode = 27,
    UnknownDataAllZeros = 31,

    Pong = 73,
    PongAck = 74,
    Pause = 75,

    ProductInfo = 80,
    LegacyWelcome = 105,
    PreferredLocale = 116,
    LicenseVersion = 118,

    TrackEndedTime = 130,

    Login = 171,
    APWelcome = 172,
    AuthFailure = 173,

    MercuryReq = 178,
    MercurySub = 179,
    MercuryUnsub = 180,
    MercuryEvent = 181,

    Unknown = 255,
}

impl From<u8> for PacketType {
    #[inline]
    fn from(v: u8) -> Self {
        match v {
            2 => Self::SecretBlock,
            4 => Self::Ping,
            8 => Self::StreamChunk,
            9 => Self::StreamChunkRes,
            10 => Self::ChannelError,
            11 => Self::ChannelAbort,
            12 => Self::RequestKey,
            13 => Self::AesKey,
            14 => Self::AesKeyError,

            25 => Self::Image,
            27 => Self::CountryCode,
            31 => Self::UnknownDataAllZeros,

            73 => Self::Pong,
            74 => Self::PongAck,
            75 => Self::Pause,

            80 => Self::ProductInfo,
            105 => Self::LegacyWelcome,
            116 => Self::PreferredLocale,
            118 => Self::LicenseVersion,

            130 => Self::TrackEndedTime,

            171 => Self::Login,
            172 => Self::APWelcome,
            173 => Self::AuthFailure,

            178 => Self::MercuryReq,
            179 => Self::MercurySub,
            180 => Self::MercuryUnsub,
            181 => Self::MercuryEvent,

            _ => Self::Unknown,
        }
    }
}
