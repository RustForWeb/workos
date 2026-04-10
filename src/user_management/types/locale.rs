use serde::{Deserialize, Serialize};

/// Locale.
///
/// [WorkOS Docs: Localization](https://workos.com/docs/authkit/hosted-ui#localization).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]

pub enum Locale {
    /// Afrikaans
    #[serde(rename = "af")]
    Af,

    /// Amharic
    #[serde(rename = "am")]
    Am,

    /// Arabic
    #[serde(rename = "ar")]
    Ar,

    /// Bulgarian
    #[serde(rename = "bg")]
    Bg,

    /// Bengali (Bangla)
    #[serde(rename = "bn")]
    Bn,

    /// Bosnian
    #[serde(rename = "bs")]
    Bs,

    /// Catalan
    #[serde(rename = "ca")]
    Ca,

    /// Czech
    #[serde(rename = "cs")]
    Cs,

    /// Danish
    #[serde(rename = "da")]
    Da,

    /// German
    #[serde(rename = "de")]
    De,

    /// German (Germany)
    #[serde(rename = "de-DE")]
    DeDe,

    /// Greek
    #[serde(rename = "el")]
    El,

    /// English
    #[serde(rename = "en")]
    En,

    /// English (Australia)
    #[serde(rename = "en-AU")]
    EnAu,

    /// English (Canada)
    #[serde(rename = "en-CA")]
    EnCa,

    /// English (UK)
    #[serde(rename = "en-GB")]
    EnGb,

    /// English (US)
    #[serde(rename = "en-US")]
    EnUs,

    /// Spanish
    #[serde(rename = "es")]
    Es,

    /// Spanish (Latin America)
    #[serde(rename = "es-419")]
    Es419,

    /// Spanish (Spain)
    #[serde(rename = "es-ES")]
    EsEs,

    /// Spanish (US)
    #[serde(rename = "es-US")]
    EsUs,

    /// Estonian
    #[serde(rename = "et")]
    Et,

    /// Farsi (Persian)
    #[serde(rename = "fa")]
    Fa,

    /// Finnish
    #[serde(rename = "fi")]
    Fi,

    /// Filipino (Tagalog)
    #[serde(rename = "fil")]
    Fil,

    /// French
    #[serde(rename = "fr")]
    Fr,

    /// French (Belgium)
    #[serde(rename = "fr-BE")]
    FrBe,

    /// French (Canada)
    #[serde(rename = "fr-CA")]
    FrCa,

    /// French (France)
    #[serde(rename = "fr-FR")]
    FrFr,

    /// Frisian
    #[serde(rename = "fy")]
    Fy,

    /// Galician
    #[serde(rename = "gl")]
    Gl,

    /// Gujarati
    #[serde(rename = "gu")]
    Gu,

    /// Hausa
    #[serde(rename = "ha")]
    Ha,

    /// Hebrew
    #[serde(rename = "he")]
    He,

    /// Hindi
    #[serde(rename = "hi")]
    Hi,

    /// Croatian
    #[serde(rename = "hr")]
    Hr,

    /// Hungarian
    #[serde(rename = "hu")]
    Hu,

    /// Armenian
    #[serde(rename = "hy")]
    Hy,

    /// Indonesian
    #[serde(rename = "id")]
    Id,

    /// Icelandic
    #[serde(rename = "is")]
    Is,

    /// Italian
    #[serde(rename = "it")]
    It,

    /// Italian (Italy)
    #[serde(rename = "it-IT")]
    ItIt,

    /// Japanese
    #[serde(rename = "ja")]
    Ja,

    /// Javanese
    #[serde(rename = "jv")]
    Jv,

    /// Georgian
    #[serde(rename = "ka")]
    Ka,

    /// Kazakh
    #[serde(rename = "kk")]
    Kk,

    /// Khmer
    #[serde(rename = "km")]
    Km,

    /// Kannada
    #[serde(rename = "kn")]
    Kn,

    /// Korean
    #[serde(rename = "ko")]
    Ko,

    /// Lithuanian
    #[serde(rename = "lt")]
    Lt,

    /// Latvian
    #[serde(rename = "lv")]
    Lv,

    /// Macedonian
    #[serde(rename = "mk")]
    Mk,

    /// Malayalam
    #[serde(rename = "ml")]
    Ml,

    /// Mongolian
    #[serde(rename = "mn")]
    Mn,

    /// Marathi
    #[serde(rename = "mr")]
    Mr,

    /// Malay
    #[serde(rename = "ms")]
    Ms,

    /// Burmese
    #[serde(rename = "my")]
    My,

    /// Norwegian Bokmål
    #[serde(rename = "nb")]
    Nb,

    /// Nepali
    #[serde(rename = "ne")]
    Ne,

    /// Dutch
    #[serde(rename = "nl")]
    Nl,

    /// Flemish
    #[serde(rename = "nl-BE")]
    NlBe,

    /// Dutch (Netherlands)
    #[serde(rename = "nl-NL")]
    NlNl,

    /// Norwegian Nynorsk
    #[serde(rename = "nn")]
    Nn,

    /// Norwegian
    #[serde(rename = "no")]
    No,

    /// Punjabi
    #[serde(rename = "pa")]
    Pa,

    /// Polish
    #[serde(rename = "pl")]
    Pl,

    /// Portuguese
    #[serde(rename = "pt")]
    Pt,

    /// Portuguese (Brazil)
    #[serde(rename = "pt-BR")]
    PtBr,

    /// Portuguese (Portugal)
    #[serde(rename = "pt-PT")]
    PtPt,

    /// Romanian
    #[serde(rename = "ro")]
    Ro,

    /// Russian
    #[serde(rename = "ru")]
    Ru,

    /// Slovak
    #[serde(rename = "sk")]
    Sk,

    /// Slovenian
    #[serde(rename = "sl")]
    Sl,

    /// Albanian
    #[serde(rename = "sq")]
    Sq,

    /// Serbian
    #[serde(rename = "sr")]
    Sr,

    /// Swedish
    #[serde(rename = "sv")]
    Sv,

    /// Swahili
    #[serde(rename = "sw")]
    Sw,

    /// Tamil
    #[serde(rename = "ta")]
    Ta,

    /// Telgu
    #[serde(rename = "te")]
    Te,

    /// Thai
    #[serde(rename = "th")]
    Th,

    /// Turkish
    #[serde(rename = "tr")]
    Tr,

    /// Ukrainian
    #[serde(rename = "uk")]
    Uk,

    /// Urdu
    #[serde(rename = "ur")]
    Ur,

    /// Uzbek
    #[serde(rename = "uz")]
    Uz,

    /// Vietnamese
    #[serde(rename = "vi")]
    Vi,

    /// Chinese
    #[serde(rename = "zh")]
    Zh,

    /// Chinese (Simplified)
    #[serde(rename = "zh-CN")]
    ZhCn,

    /// Chinese (Hong Kong)
    #[serde(rename = "zh-HK")]
    ZhHk,

    /// Chinese (Taiwan)
    #[serde(rename = "zh-TW")]
    ZhTw,

    /// Zulu
    #[serde(rename = "zu")]
    Zu,

    /// Unknown locale.
    #[serde(untagged)]
    Unknown(String),
}
