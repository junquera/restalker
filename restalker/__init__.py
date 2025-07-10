from .restalker import (
    reStalker,
    Item,
    PhoneNumber,
    EmailAddress,
    KeyPhrase,
    Keyword,
    BitcoinAddress,
    EthereumAddress,
    MoneroAddress,
    ZcashAddress,
    DashAddress,
    PolkadotAddress,
    RippleAddress,
    BinanceAddress,
    TwitterAccount,
    OnionAddress,
    I2pAddress,
    FreenetAddress,
    ZeronetAddress,
    BitnameAddress,
    IpfsAddress,
    Username,
    Password,
    Base64,
    PersonName,
    TelegramUrl,
    WhatsappUrl,
    SkypeUrl,
    DiscordUrl,
    PasteUrl,
    Md5Hash,
    Sha1Hash,
    Sha256Hash,
    Organization,
    Location,
    PgpKey,
    GoogleAnalyticsTrackingCode,
    CreditCardNumber,
    SessionId,
    ToxId
)
from . import link_extractors as link_extractors

import nltk
nltk.download('stopwords')
nltk.download('punkt')


__version__ = "2.0.6"
