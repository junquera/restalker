from .restalker import (
    reStalker,
    Item,
    Phone,
    Email,
    Keyphrase,
    Keyword,
    BTC_Wallet,
    ETH_Wallet,
    XMR_Wallet,
    ZEC_Wallet,
    DASH_Wallet,
    DOT_Wallet,
    XRP_Wallet,
    BNB_Wallet,
    TW_Account,
    Tor_URL,
    I2P_URL,
    Freenet_URL,
    Zeronet_URL,
    Bitname_URL,
    IPFS_URL,
    Username,
    Password,
    Base64,
    OwnName,
    Telegram_URL,
    Whatsapp_URL,
    Skype_URL,
    Discord_URL,
    Paste,
    MD5,
    SHA1,
    SHA256,
    Organization,
    Location,
    PGP,
    GA_Tracking_Code,
    Card_Number,
    Session_ID,
    Tox_ID
)
from . import link_extractors as link_extractors

import spacy

# Load models
def load_spacy_model():
    try:
        return spacy.load("es_core_news_md")
    except OSError:
        try:
            return spacy.load("en_core_web_md")
        except OSError:
            # Download smallermodels if error
            print("Descargando modelo de spaCy...")
            spacy.cli.download("en_core_web_sm")
            return spacy.load("en_core_web_sm")


__version__ = "2.0.9"
