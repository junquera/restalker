import based58
from hashlib import sha256
from bech32ref import segwit_addr
from web3 import Web3
from monero.address import address as xmr_address
from bip_utils import SS58Decoder
from .link_extractors import UUF
from urllib.parse import urljoin
from bs4 import BeautifulSoup
import re
import nltk
from .textan import TextAnalysis


class Item:
    def __init__(self, value=None):
        self.value = value

    def __eq__(self, other):
        if not isinstance(other, Item):
            return False
        
        return self.value == other.value and type(self).__name__ == type(other).__name__

    def __hash__(self):
        return hash(type(self).__name__ + str(self.value))

    def __str__(self):
        return f"{type(self).__name__}({self.value[:128]})"

    def __repr__(self):
        return f"{type(self).__name__}({self.value[:128]})"


class Phone(Item):
    pass


class Email(Item):
    pass


class Keyphrase(Item):
    pass


class Keyword(Item):
    pass


class BTC_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            if address[0] in ["1", "3"]:
                decode_address = based58.b58decode(address.encode("utf-8"))
                ret = (
                    decode_address[-4:] == sha256(sha256(decode_address[:-4]).digest()).digest()[:4]
                )
            elif address.startswith("bc"):
                hrpgot, data, spec = segwit_addr.bech32_decode(address)
                ret = (hrpgot is not None) and (data is not None) and (spec is not None)
        finally:
            return ret


class ETH_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            ret = Web3.is_address(address)
        except:
            ret = False
        return ret

class XMR_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            # Remove any whitespace from the address
            clean_address = ''.join(address.split())
            ret = xmr_address(clean_address) is not None
        except:
            ret = False
        return ret


class ZEC_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            if (address[0] == "t" and address[1] in ["1", "3"]) or address.startswith(
                "zc"
            ):
                decode_address = based58.b58decode(address.encode("utf-8"))
                ret = (
                    decode_address[-4:] == sha256(sha256(decode_address[:-4]).digest()).digest()[:4]
                )
            elif address.startswith("zs"):
                hrpgot, data, spec = segwit_addr.bech32_decode(address)
                ret = (hrpgot is not None) and (data is not None) and (spec is not None)
        finally:
            return ret


class DASH_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            if re.search(dash_wallet_regex, address)[0] == address:
                decode_address = based58.b58decode(address.encode("utf-8"))
                ret = (
                    decode_address[-4:] == sha256(sha256(decode_address[:-4]).digest()).digest()[:4]
                )
        finally:
            return ret


class DOT_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            if re.search(dot_wallet_regex, address)[0] == address:
                prefix, decode = SS58Decoder.Decode(address)
                ret = prefix == 0
        finally:
            return ret


class XRP_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            if re.search(xrp_wallet_regex, address)[0] == address:
                based58.b58decode_check(
                    address.encode("utf-8"),
                    alphabet=based58.Alphabet.RIPPLE,
                )
                ret = True
        finally:
            return ret


class BNB_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            if re.search(bnb_wallet_regex, address)[0] == address:
                hrpgot, data, spec = segwit_addr.bech32_decode(address)
                ret = hrpgot == "bnb"
        finally:
            return ret


class TW_Account(Item):
    pass


class Tor_URL(Item):
    pass


class I2P_URL(Item):
    pass


class Freenet_URL(Item):
    pass


class Zeronet_URL(Item):
    pass


class Bitname_URL(Item):
    pass


class IPFS_URL(Item):
    pass


class Username(Item):
    pass


class Password(Item):
    pass


class Base64(Item):
    pass


class OwnName(Item):
    pass


class Telegram_URL(Item):
    pass


class Whatsapp_URL(Item):
    pass


class Skype_URL(Item):
    pass


class Discord_URL(Item):
    pass


class Paste(Item):
    pass


class MD5(Item):
    pass


class SHA1(Item):
    pass


class SHA256(Item):
    pass


class Organization(Item):
    pass


class Location(Item):
    pass


class PGP(Item):
    def __init__(self, value):
        self.value = self.clean_pgp_key(value)

    def is_public_key(self):
        return "PUBLIC KEY" in self.value

    def is_private_key(self):
        return "PRIVATE KEY" in self.value

    @staticmethod
    def clean_pgp_key(pgp_key):
        cleaned_key = re.sub(r'<br\s*/?>', '', pgp_key)
        cleaned_key = cleaned_key.strip()
        return cleaned_key


class GA_Tracking_Code(Item):
    @staticmethod
    def isvalid(code: str) -> bool:
        # Validate that the code is not part of a larger string
        return bool(re.fullmatch(r'(?:UA-\d{4,10}-\d|G-[A-Za-z0-9]{10})', code))

class Card_Number(Item):

    @staticmethod
    def isvalid(number: str) -> bool:

        def luhn_check(card_number: str) -> bool:
            digits = [int(d) for d in str(card_number)]
            odd_digits = digits[-1::-2]
            even_digits = digits[-2::-2]
            checksum = sum(odd_digits)
            for d in even_digits:
                checksum += sum(divmod(d * 2, 10))
            return checksum % 10 == 0

        return luhn_check(number)

class Session_ID(Item):
    @staticmethod
    def isvalid(session_id: str) -> bool:

        if not isinstance(session_id, str):
            return False
            
        if len(session_id) != 66:
            return False

        try:
            int(session_id, 16)  # Esto falla si no es hexadecimal válido
            return True
        except ValueError:
            return False


class Tox_ID(Item):
    @staticmethod
    def isvalid(tox_id: str) -> bool:
        """Verify if the string is a valid Tox ID - 76 hexadecimal chars (64 public key + 4 NoSpam + 2 checksum)"""
        ret = None
        try:
            # Check if it's a valid 76-character hexadecimal string
            if len(tox_id) == 76 and all(c in '0123456789ABCDEFabcdef' for c in tox_id):
                # Convert the Tox ID from hexadecimal to bytes
                tox_id_bytes = bytes.fromhex(tox_id)
                
                # The ID is 38 bytes: 32 bytes public key + 4 bytes NoSpam + 2 bytes checksum
                # Extract the checksum (last 2 bytes)
                actual_checksum = tox_id_bytes[36:38]
                
                # Calculate the checksum by XORing pairs of bytes
                calculated_checksum = bytearray(2)
                for i in range(0, 36, 2):
                    calculated_checksum[0] ^= tox_id_bytes[i]
                    calculated_checksum[1] ^= tox_id_bytes[i+1]
                
                # Verify that the calculated checksum matches the actual checksum
                ret = (actual_checksum == calculated_checksum)
            else:
                ret = False
        except Exception as e:
            ret = False
        return ret

# Precompiled regex patterns - will improve performance by compiling only once
number_regex_pattern = r"[0-9]+"
NUMBER_REGEX = re.compile(number_regex_pattern, re.DOTALL)

alnum_join_pattern = r"[a-zA-Z0-9\-\~]+"
ALNUM_JOIN = re.compile(alnum_join_pattern, re.DOTALL)

file_name_pattern = r"(?:[a-zA-Z0-9\_]+\.)+\.[a-zA-Z0-9]{2,4}"
FILE_NAME = re.compile(file_name_pattern, re.DOTALL)

phone_regex_pattern = r"(\(?\+[0-9]{1,3}\)? ?-?[0-9]{1,3} ?-?[0-9]{3,5} ?-?[0-9]{4}( ?-?[0-9]{3})? ?(\w{1,10}\s?\d{1,6})?)"
PHONE_REGEX = re.compile(phone_regex_pattern, re.DOTALL)

email_regex_pattern = r"([a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)+(?:[0-9][a-zA-Z0-9]{0,4}[a-zA-Z]|[0-9][a-zA-Z][a-zA-Z0-9]{0,4}|[a-zA-Z][a-zA-Z0-9]{1,5}))"
EMAIL_REGEX = re.compile(email_regex_pattern, re.DOTALL)

btc_wallet_regex_pattern = r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})"
BTC_WALLET_REGEX = re.compile(btc_wallet_regex_pattern, re.DOTALL)

btc_wallet_bech32_regex_pattern = r"(bc1[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,58})"
BTC_WALLET_BECH32_REGEX = re.compile(btc_wallet_bech32_regex_pattern, re.DOTALL)

eth_wallet_regex_pattern = r"(0x[0-9a-fA-F]{40})"
ETH_WALLET_REGEX = re.compile(eth_wallet_regex_pattern, re.DOTALL)

xmr_wallet_regex_pattern = r"([48][a-km-zA-HJ-NP-Z1-9]{94,105})"
XMR_WALLET_REGEX = re.compile(xmr_wallet_regex_pattern, re.DOTALL)

zec_wallet_transparent_regex_pattern = r"(t[13][a-km-zA-HJ-NP-Z1-9]{33})"
ZEC_WALLET_TRANSPARENT_REGEX = re.compile(zec_wallet_transparent_regex_pattern, re.DOTALL)

zec_wallet_private_regex_pattern = r"(zc[a-km-zA-HJ-NP-Z1-9]{93})"
ZEC_WALLET_PRIVATE_REGEX = re.compile(zec_wallet_private_regex_pattern, re.DOTALL)

zec_wallet_private_sapling_regex_pattern = r"(zs1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{75})"
ZEC_WALLET_PRIVATE_SAPLING_REGEX = re.compile(zec_wallet_private_sapling_regex_pattern, re.DOTALL)

dash_wallet_regex_pattern = r"(X[a-km-zA-HJ-NP-Z1-9]{33})"
DASH_WALLET_REGEX = re.compile(dash_wallet_regex_pattern, re.DOTALL)

dot_wallet_regex_pattern = r"(1[a-km-zA-HJ-NP-Z1-9]{46,47})"
DOT_WALLET_REGEX = re.compile(dot_wallet_regex_pattern, re.DOTALL)

xrp_wallet_regex_pattern = r"([rX][rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{26,46})"
XRP_WALLET_REGEX = re.compile(xrp_wallet_regex_pattern, re.DOTALL)

bnb_wallet_regex_pattern = r"(bnb[a-zA-Z0-9]{39})"
BNB_WALLET_REGEX = re.compile(bnb_wallet_regex_pattern, re.DOTALL)

bitname_domain_regex_pattern = r"(?:[a-zA-Z0-9]+\.)+bit"
BITNAME_DOMAIN_REGEX = re.compile(bitname_domain_regex_pattern, re.DOTALL)

tw_account_regex_pattern = r"[^a-zA-Z0-9]@([a-zA-Z0-9_]{3,15})"
TW_ACCOUNT_REGEX = re.compile(tw_account_regex_pattern, re.DOTALL)

telegram_url_regex_pattern = r"((?:https?\:\/\/)?(?:t\.me|telegram\.me|telegram\.dog)(?:\/(?:joinchat|c|\+)?[a-zA-Z0-9_-]+(?:\/[0-9]+)?)+)"
TELEGRAM_URL_REGEX = re.compile(telegram_url_regex_pattern, re.DOTALL)

whatsapp_url_regex_pattern = r"((?:https?\:\/\/)?(?:wa\.me|api\.whatsapp\.com\/send|chat\.whatsapp\.com)(?:\/(?:invite\/)?[a-zA-Z0-9_-]+)*(?:\?(?:[^=]+=[^&\s]+)(?:&[^=]+=[^&\s]+)*)?)"
WHATSAPP_URL_REGEX = re.compile(whatsapp_url_regex_pattern, re.DOTALL)

discord_url_regex_pattern = r"((?:https?\:\/\/)?(?:discord(?:app)?\.(?:gg|com|io|me)|discord\.(?:com\/invite))(?:\/[a-zA-Z0-9_-]+)+)"
DISCORD_URL_REGEX = re.compile(discord_url_regex_pattern, re.DOTALL)

skype_url_regex_pattern = r"((?:skype\:\/\/join\?id=[a-zA-Z0-9_-]+|skype\:([^?\s]+)(?:\?(?:call|chat|add))?|(?:https?\:\/\/)?join\.skype\.com(?:\/invite)?(?:\/[a-zA-Z0-9_-]+)+))"
SKYPE_URL_REGEX = re.compile(skype_url_regex_pattern, re.DOTALL)

username_regex_pattern = r"([a-zA-Z0-9\$\.,;_-]{8,20})[^a-zA-Z0-9]"
USERNAME_REGEX = re.compile(username_regex_pattern, re.DOTALL)

password_regex_pattern = r"(?:[Pp]ass(?:word)?.|[a-zA-Z0-9_-]\:\s?)([a-zA-Z0-9$,;_-]{4,16})"
PASSWORD_REGEX = re.compile(password_regex_pattern, re.DOTALL)

base64_regex_pattern = r"((?:[a-zA-Z0-9\+\/]{4})+(?:[a-zA-Z0-9\+\/]{3}[=]|[a-zA-Z0-9\+\/]{2}[=]{2}))"
BASE64_REGEX = re.compile(base64_regex_pattern, re.DOTALL)

own_name_regex_pattern = r"([A-Z][a-z]{2,10} [A-Z][a-z]{2,10})"
OWN_NAME_REGEX = re.compile(own_name_regex_pattern, re.DOTALL)

domain_regex_pattern = r"(?:[a-z0-9]+\.){0,4}[a-z0-9]+\.?(?:\:[0-9]{2,5})?$"
DOMAIN_REGEX = re.compile(domain_regex_pattern, re.DOTALL)

any_url_pattern = r"((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)" % domain_regex_pattern[:-1]
ANY_URL = re.compile(any_url_pattern, re.DOTALL)

tor_hidden_domain_pattern = r"(?:[a-z0-9]+\.){0,4}(?:[a-z0-9]{16}|[a-z0-9]{56})\.onion(?:\:[0-9]{2,5})?$"
TOR_HIDDEN_DOMAIN = re.compile(tor_hidden_domain_pattern, re.DOTALL)

tor_hidden_url_pattern = r"((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)" % tor_hidden_domain_pattern[:-1]
TOR_HIDDEN_URL = re.compile(tor_hidden_url_pattern, re.DOTALL)

i2p_hidden_domain_pattern = r"(?:[a-z0-9]+\.){1,5}i2p(?:\:[0-9]{2,5})?$"
I2P_HIDDEN_DOMAIN = re.compile(i2p_hidden_domain_pattern, re.DOTALL)

i2p_hidden_url_pattern = r"((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)" % i2p_hidden_domain_pattern[:-1]
I2P_HIDDEN_URL = re.compile(i2p_hidden_url_pattern, re.DOTALL)

# Keep the original pattern strings for reference or in case they're needed elsewhere
number_regex = number_regex_pattern
alnum_join = alnum_join_pattern
file_name = file_name_pattern
phone_regex = phone_regex_pattern
email_regex = email_regex_pattern
btc_wallet_regex = btc_wallet_regex_pattern
btc_wallet_bech32_regex = btc_wallet_bech32_regex_pattern
eth_wallet_regex = eth_wallet_regex_pattern
xmr_wallet_regex = xmr_wallet_regex_pattern
zec_wallet_transparent_regex = zec_wallet_transparent_regex_pattern
zec_wallet_private_regex = zec_wallet_private_regex_pattern
zec_wallet_private_sapling_regex = zec_wallet_private_sapling_regex_pattern
dash_wallet_regex = dash_wallet_regex_pattern
dot_wallet_regex = dot_wallet_regex_pattern
xrp_wallet_regex = xrp_wallet_regex_pattern
bnb_wallet_regex = bnb_wallet_regex_pattern
bitname_domain_regex = bitname_domain_regex_pattern
tw_account_regex = tw_account_regex_pattern
telegram_url_regex = telegram_url_regex_pattern
whatsapp_url_regex = whatsapp_url_regex_pattern
discord_url_regex = discord_url_regex_pattern
skype_url_regex = skype_url_regex_pattern
username_regex = username_regex_pattern
password_regex = password_regex_pattern
base64_regex = base64_regex_pattern
own_name_regex = own_name_regex_pattern
domain_regex = domain_regex_pattern
any_url = any_url_pattern
tor_hidden_domain = tor_hidden_domain_pattern
tor_hidden_url = tor_hidden_url_pattern
i2p_hidden_domain = i2p_hidden_domain_pattern
i2p_hidden_url = i2p_hidden_url_pattern

card_regex = {
    # American Express - 34, 37 - length 15
    "American_Express": r"3[47][0-9]{13}",
    
    # China T-Union - 31 - length 19
    "China_T_Union": r"31[0-9]{17}",
    
    # China UnionPay - 62 - length 16-19
    "China_UnionPay": r"62[0-9]{14,17}",
    
    # Diners Club enRoute - 2014, 2149 - length 15
    "Diners_Club_enRoute": r"2014[0-9]{11}|2149[0-9]{11}",
    
    # Diners Club International - 30, 36, 38, 39 - length 14-19
    "Diners_Club_International": r"3(?:0[0-5]|[68][0-9]|9)[0-9]{11,16}",
    
    # Diners Club United States & Canada - 54, 55 - length 16
    "Diners_Club_US_CA": r"5[45][0-9]{14}",
    
    # Discover - 6011, 644-649, 65, 622126-622925 - length 16-19
    "Discover": r"6011[0-9]{12,15}|64[4-9][0-9]{13,16}|65[0-9]{14,17}|622(?:12[6-9]|1[3-9][0-9]|[2-8][0-9][0-9]|9[0-1][0-9]|92[0-5])[0-9]{10,13}",
    
    # UkrCard - 60400100-60420099 - length 16-19
    "UkrCard": r"6042[0-9]{12,15}|6040[0-9]{12,15}|6041[0-9]{12,15}",
    
    # RuPay - 60, 65, 81, 82, 508, 353, 356 - length 16
    "RuPay": r"(?:508|6[05]|8[12])[0-9]{14}|35[36][0-9]{13}",
    
    # InterPayment - 636 - length 16-19
    "InterPayment": r"636[0-9]{13,16}",
    
    # InstaPayment - 637-639 - length 16
    "InstaPayment": r"63[7-9][0-9]{13}",
    
    # JCB - 3528-3589 - length 16-19
    "JCB": r"(?:352[8-9]|35[3-8][0-9])[0-9]{12,15}",
    
    # Maestro - 5018, 5020, 5038, 5893, 6304, 6759, 6761-6763 - length 12-19
    "Maestro": r"(?:5018|5020|5038|5893|6304|6759|676[1-3])[0-9]{8,15}",
    
    # Maestro UK - 6759, 676770, 676774 - length 12-19
    "Maestro_UK": r"(?:6759|676770|676774)[0-9]{8,15}",
    
    # Dankort - 5019, 4571 - length 16
    "Dankort": r"5019[0-9]{12}|4571[0-9]{12}",
    
    # Mir - 2200-2204 - length 16-19
    "Mir": r"220[0-4][0-9]{12,15}",
    
    # BORICA - 2205 - length 16
    "BORICA": r"2205[0-9]{12}",
    
    # Mastercard - 2221-2720, 51-55 - length 16
    "Mastercard": r"(?:222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[0-1][0-9]|2720|5[1-5][0-9]{2})[0-9]{12}",
    
    # Troy - 65, 9792 - length 16
    "Troy": r"(?:65|9792)[0-9]{14}",
    
    # Visa - 4 - length 13,16,19
    "Visa": r"4[0-9]{12}(?:[0-9]{3,6})?",
    
    # Visa Electron - 4026, 417500, 4844, 4913, 4917 - length 16
    "Visa_Electron": r"(?:4026|417500|4844|4913|4917)[0-9]{10}",
    
    # UATP - 1 - length 15
    "UATP": r"1[0-9]{14}",
    
    # Verve - 506099-506198, 650002-650027, 507865-507964 - length 16,18,19
    "Verve": r"(?:506(?:0[9][9]|1[0-8][0-9])|650(?:0[0-1][0-9]|02[0-7])|507(?:8[6-9][0-9]|9[0-6][0-9]))[0-9]{10}(?:[0-9]{2,3})?",
    
    # LankaPay - 357111 - length 16
    "LankaPay": r"357111[0-9]{10}",
    
    # Uzcard - 8600, 5614 - length 16
    "Uzcard": r"(?:8600|5614)[0-9]{12}",
    
    # HUMO - 9860 - length 16
    "HUMO": r"9860[0-9]{12}",
    
    # GPN - 1946, 50, 56, 58, 60-63 - length 16,18,19
    "GPN": r"(?:1946|5[068]|6[0-3])[0-9]{12}(?:[0-9]{2,3})?",
    
    # Napas - 9704 - length 16,19
    "Napas": r"9704[0-9]{12}(?:[0-9]{3})?"
}

# Regex combinada para todas las tarjetas
all_card_regex = r"(?:" + "|".join(card_regex.values()) + r")"

# Add BIN and generic credit card number regex
bin_regex = r"\b\d{6,8}\b"  # BIN/IIN: 6 or 8 digits
ccn_regex = r"\b\d{8,19}\b"  # Payment card number: 8-19 digits

http_regex = r"(?:https?\:\/\/)"
localhost_regex = r"(?:localhost|127\.0\.0\.1)"
# TODO Add query parameters
path_regex = r"(?:\/[a-zA-Z0-9_-]+)*"


def port_regex(p):
    return r"(?:\:%d)?" % (p)


zeronet_params = dict(
    http=http_regex,
    localhost=localhost_regex,
    port=port_regex(43110),
    path=path_regex,
    bitcoin=btc_wallet_regex,
    bitname=bitname_domain_regex,
)


bitname_url = r"((?:{http})?(?:{bitcoin}|{bitname})(?:{port})?(?:{path})?)".format(
    **zeronet_params
)

zeronet_params["bitname_url"] = bitname_url
zeronet_hidden_url = r"(?:(?:{http}?{localhost}{port}\/)({bitname_url}))".format(
    **zeronet_params
)

pgp_header = r'-----BEGIN PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----'
pgp_footer = r'-----END PGP (?:PUBLIC|PRIVATE) KEY BLOCK-----'

pgp_key = r"(%s[\s\S]{175,5000}%s)" % (pgp_header, pgp_footer)


ga_tracking_code_regex = r"\b(UA-\d{4,10}-\d|G-[A-Za-z0-9]{10})\b"

session_id_regex = r"(?<![0-9a-fA-F])[0-9a-fA-F]{66}(?![0-9a-fA-F])"

tox_id_regex = r"([a-fA-F0-9]{76})"

"""
Freenet URL spec:
    - CHK@file hash,decryption key,crypto settings
    CHK@SVbD9~HM5nzf3AX4yFCBc-A4dhNUF5DPJZLL5NX5Brs,bA7qLNJR7IXRKn6uS5PAySjIM6azPFvK~18kSi6bbNQ,AAEA--8
    - SSK@public key hash,decryption key,crypto settings/user selected name-version
    SSK@GB3wuHmt[..]o-eHK35w,c63EzO7u[..]3YDduXDs,AQABAAE/mysite-4
    - USK@public key hash,decryption key,crypto settings/user selected name/number/
    USK@GB3wuHmt[..]o-eHK35w,c63EzO7u[..]3YDduXDs,AQABAAE/mysite/5/
    - KSK@filename
    KSK@myfile.txt

Create freenet sites:

    http://localhost:8888/freenet:USK@spOnEa2YvAoNfreZPfoy0tVNCzQghLdWaaNM10GEiEM,QRKjyaBkOX5Qw~aEml19WIDaJJo2X3hU9mGz8GcUuKc,AQACAAE/freesite_es/11/
"""

freenet_terms = dict(
    file_hash=alnum_join,
    decryption_key=alnum_join,
    crypto_settings=r"[A-Z]+(?:\-\-[0-9]+)?",
    public_key=alnum_join,
    user_selected_name=r"[a-zA-Z0-9\\_]+",
    version=number_regex,
    file_name=file_name,
)

freenet_keys = dict(
    chk="CHK@{file_hash},{decryption_key},{crypto_settings}",
    ssk="SSK@{public_key},{decryption_key},{crypto_settings}\\/{user_selected_name}\\-{version}",
    usk="USK@{public_key},{decryption_key},{crypto_settings}\\/{user_selected_name}\\/{version}",
    ksk="KSK@{file_name}",
)

for k in freenet_keys:
    freenet_keys[k] = freenet_keys[k].format(**freenet_terms)

freenet_hash = r"(?:{chk}|{ssk}|{usk}|{ksk})".format(**freenet_keys)

freenet_params = dict(
    http=http_regex,
    localhost=localhost_regex,
    port=port_regex(8888),
    path=path_regex,
    freenet_hash=freenet_hash,
)
freenet_hidden_url = r"(?:(?:{http}?{localhost}{port})\/)?(?:freenet\:)?((?:{freenet_hash})(?:{path}))".format(
    **freenet_params
)

"""
http://localhost:8080/ipfs/QmW2WQi7j6c7UgJTarActp7tDNikE4B2qXtFCfLPdsgaTQ
"""
# Regular expressions for IPFS
# CIDv0 starts with Qm 
# CIDv1 usually starts with baf... and uses base32
# Rule of thumb: use len >= 46 for both v0 and v1 to avoid false positives
ipfs_cid = r"(?:Qm[a-zA-Z0-9]{44}|b[a-z2-7]{45,})"
ipns_name = r"(?:k[a-z2-7]{45,}|[a-z0-9]+(?:\.[a-z0-9]+)*)"
ipfs_path = r"(?:\/[^\/\s\?#]+)*"
ipfs_params = r"(?:\?[^\s#]*)?"
ipfs_fragment = r"(?:#[^\s]*)?"

# Native IPFS protocol format
ipfs_native_url = r"(?:ipfs:\/\/%s%s%s%s)" % (ipfs_cid, ipfs_path, ipfs_params, ipfs_fragment)
ipns_native_url = r"(?:ipns:\/\/%s%s%s%s)" % (ipns_name, ipfs_path, ipfs_params, ipfs_fragment)

# Path gateway format
ipfs_gateway = r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}"
ipfs_gateway_port = r"(?::[0-9]{1,5})?"
ipfs_gateway_url = r"(?:https?:\/\/%s%s\/ipfs\/%s%s%s%s)" % (ipfs_gateway, ipfs_gateway_port, ipfs_cid, ipfs_path, ipfs_params, ipfs_fragment)
ipns_gateway_url = r"(?:https?:\/\/%s%s\/ipns\/%s%s%s%s)" % (ipfs_gateway, ipfs_gateway_port, ipns_name, ipfs_path, ipfs_params, ipfs_fragment)

# Subdomain gateway format
ipfs_subdomain_url = r"(?:https?:\/\/%s\.ipfs\.%s%s%s%s%s)" % (ipfs_cid, ipfs_gateway, ipfs_gateway_port, ipfs_path, ipfs_params, ipfs_fragment)
ipns_subdomain_url = r"(?:https?:\/\/%s\.ipns\.%s%s%s%s%s)" % (ipns_name, ipfs_gateway, ipfs_gateway_port, ipfs_path, ipfs_params, ipfs_fragment)

# Combined regex for any IPFS URL
ipfs_url = r"(%s|%s|%s|%s|%s|%s)" % (
    ipfs_native_url, 
    ipns_native_url,
    ipfs_gateway_url,
    ipns_gateway_url, 
    ipfs_subdomain_url,
    ipns_subdomain_url
)

pastes = [
    "justpaste.it",
    "pastebin.com",
    "pasted.co",
    "hastebin.com",
    "snipt.org",
    "gist.github.com",
    "telegra.ph",
    "ghostbin.com",
]

# Additional precompiled regex patterns
paste_url_regex_pattern = r"((?:https?\:\/\/)?(?:%s)(?:\/[a-zA-Z0-9_-]+)+)" % ("|".join(pastes))
PASTE_URL_REGEX = re.compile(paste_url_regex_pattern, re.DOTALL)

md5_regex_pattern = r"[a-f0-9]{32}"
MD5_REGEX = re.compile(md5_regex_pattern, re.DOTALL)

sha1_regex_pattern = r"[a-f0-9]{40}"
SHA1_REGEX = re.compile(sha1_regex_pattern, re.DOTALL)

sha256_regex_pattern = r"[a-f0-9]{64}"
SHA256_REGEX = re.compile(sha256_regex_pattern, re.DOTALL)

ga_tracking_code_regex_pattern = r"\b(UA-\d{4,10}-\d|G-[A-Za-z0-9]{10})\b"
GA_TRACKING_CODE_REGEX = re.compile(ga_tracking_code_regex_pattern, re.DOTALL)

session_id_regex_pattern = r"(?<![0-9a-fA-F])[0-9a-fA-F]{66}(?![0-9a-fA-F])"
SESSION_ID_REGEX = re.compile(session_id_regex_pattern, re.DOTALL)

tox_id_regex_pattern = r"([a-fA-F0-9]{76})"
TOX_ID_REGEX = re.compile(tox_id_regex_pattern, re.DOTALL)

# Keep original pattern strings for reference
paste_url_regex = paste_url_regex_pattern
md5_regex = md5_regex_pattern
sha1_regex = sha1_regex_pattern
sha256_regex = sha256_regex_pattern
ga_tracking_code_regex = ga_tracking_code_regex_pattern
session_id_regex = session_id_regex_pattern
tox_id_regex = tox_id_regex_pattern
def extract_elements(x):
    if x is None:
        return []
    if type(x) in [tuple, list, set]:
        result = []
        for piece in x:
            for element in extract_elements(piece):
                if element is not None and element != '':
                    result.append(element)
        return set(el for el in result if el)  # Filters out empty elements
    else:
        return [x] if x is not None and x != '' else []


class reStalker:
    def __init__(
        self,
        phone=False,
        email=False,
        btc_wallet=False,
        eth_wallet=False,
        xmr_wallet=False,
        zec_wallet=False,
        dash_wallet=False,
        dot_wallet=False,
        xrp_wallet=False,
        bnb_wallet=False,
        credit_card=False,
        bin_number=False,
        ccn_number=False,
        tor=False,
        i2p=False,
        ipfs=False,
        freenet=False,
        zeronet=False,
        zeronet_ctxt=False,
        bitname=False,
        paste=False,
        twitter=False,
        username=False,
        password=False,
        location=False,
        organization=False,
        keyphrase=False,
        keywords=[],
        pgp=False,
        gatc=False,
        base64=False,
        own_name=False,
        whatsapp=False,
        discord=False,
        telegram=False,
        skype=False,
        md5=False,
        sha1=False,
        sha256=False,
        session_id=False,
        tox=False,
        all=False,
    ):

        self.ner = own_name or location or organization
        self.own_name = own_name or all
        self.location = location or all
        self.organization = organization or all

        self.keyphrase = keyphrase or all
        self.keywords = keywords

        self.phone = phone or all
        self.email = email or all
        self.twitter = twitter or all

        self.btc_wallet = btc_wallet or all
        self.eth_wallet = eth_wallet or all
        self.xmr_wallet = xmr_wallet or all
        self.zec_wallet = zec_wallet or all
        self.dash_wallet = dash_wallet or all
        self.dot_wallet = dot_wallet or all
        self.xrp_wallet = xrp_wallet or all
        self.bnb_wallet = bnb_wallet or all

        self.credit_card = credit_card or all
        self.bin_number = bin_number or all
        self.ccn_number = ccn_number or all

        self.tor = tor or all
        self.i2p = i2p or all
        self.freenet = freenet or all
        self.zeronet_ctxt = zeronet_ctxt
        self.zeronet = zeronet or all or zeronet_ctxt
        self.bitname = bitname or all

        self.pgp = pgp or all
        self.gatc = gatc or all

        self.ipfs = ipfs or all

        self.paste = paste or all

        self.username = username or all
        self.password = password or all
        self.base64 = base64 or all
        self.whatsapp = whatsapp or all
        self.discord = discord or all
        self.telegram = telegram or all
        self.skype = skype or all

        self.md5 = md5 or all
        self.sha1 = sha1 or all
        self.sha256 = sha256 or all
        self.session_id = session_id or all
        self.tox = tox or all


    def add_keyword(self, keyword):
        self.keywords.append(keyword)

    def remove_keyword(self, keyword):
        while keyword in self.keywords:
            self.keywords.remove(keyword)

    def extract_links(self, body, origin=None, url_format=ANY_URL, domain_format=DOMAIN_REGEX):
        urls = set()

        def add_url_safely(url_str):
            """Helper function to safely add URLs to the set"""
            try:
                # Convert bytes to string if needed
                if isinstance(url_str, bytes):
                    url_str = url_str.decode('utf-8')
                
                if url_str and isinstance(url_str, str):
                    cleaned_url = UUF(url_str).rebuild()
                    if cleaned_url:
                        urls.add(cleaned_url)
            except (ValueError, AttributeError) as e:
                print(f"[*] Error processing URL {url_str}: {e}")
            except Exception as e:
                print(f"[*] Unexpected error with URL {url_str}: {e}")

        # Process URLs found with regex - handle both compiled patterns and strings
        if isinstance(url_format, str):
            url_matches = re.findall(url_format, body, re.DOTALL)
        else:
            # Already compiled pattern
            url_matches = url_format.findall(body)
            
        for url in url_matches:
            add_url_safely(url)

        try:
            # soup = BeautifulSoup(body, "html.parser")
            soup = BeautifulSoup(body, "lxml")
            if soup:
                links = soup.findAll("a")
                if links:
                    for url in links:
                        try:
                            href = url.get("href")
                            if href:
                                if origin is not None:
                                    # Make sure origin is a string
                                    if isinstance(origin, bytes):
                                        origin = origin.decode('utf-8')
                                    full_url = urljoin(origin, href)
                                else:
                                    full_url = href
                                    
                                urls.add(UUF(full_url).rebuild())
                        except AttributeError:
                            print("[*] AttributeError: Invalid attribute in URL")
                        except ValueError:
                            print("[*] ValueError: Invalid URL format")
                        except Exception as e:
                            print(f"Error parsing text with BeautifulSoup: {e}")
                            print(f"[*] Unexpected error: {e}")
        except TypeError:
            print("[*] TypeError: Invalid input type for BeautifulSoup")
        except Exception as e:
            print(f"[*] Error with HTML parsing: {e}")

        for url in urls:
            if url:
                parsed_url = UUF(url)
                # Check if domain matches the domain format
                if isinstance(domain_format, str):
                    domain_match = re.match(domain_format, parsed_url.domain, re.DOTALL)
                else:
                    # Already compiled pattern
                    domain_match = domain_format.match(parsed_url.domain)
                    
                if domain_match:
                    yield parsed_url.rebuild()

    @staticmethod
    def body_text(body):
        try:
            # TODO Can this be done with the scrapy response?
            soup = BeautifulSoup(body, "lxml")

            for script in soup(["script", "style"]):
                script.extract()  # rip it out

            text = soup.get_text()

            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = "\n".join(chunk for chunk in chunks if chunk)
        except Exception:
            text = body

        return text

    def _analyze_chunk(self, body, origin=None):
        if self.ner:
            # Text pre-processing to remove tags and improve detection
            cleaned_text = re.sub(r'(?:Location|Organization|Person|Keyphrase|BitName):\s*', '', body)
            sentences = nltk.sent_tokenize(cleaned_text)
            
            for sentence in sentences:
                # Pre-process to handle organization names with multiple words
                sentence = re.sub(r'\s+Ltd\.?$', ' Limited', sentence)
                sentence = re.sub(r'\s+Inc\.?$', ' Incorporated', sentence)
                sentence = re.sub(r'\s+Corp\.?$', ' Corporation', sentence)
                
                tokens = nltk.word_tokenize(sentence)
                pos = nltk.pos_tag(tokens)
                sentt = nltk.ne_chunk(pos, binary=False)

                if self.own_name:
                    for subtree in sentt.subtrees(filter=lambda t: t.label() == "PERSON"):
                        person_name = ' '.join([leave[0] for leave in subtree.leaves()])
                        if person_name:
                            yield OwnName(value=person_name)

                if self.organization:
                    # Search for organizations using NER
                    for subtree in sentt.subtrees(filter=lambda t: t.label() == "ORGANIZATION"):
                        org_name = ' '.join([leave[0] for leave in subtree.leaves()])
                        if org_name and not org_name.lower().startswith('organization'):
                            yield Organization(value=org_name)
                    
                    # Search for organizations using common patterns
                    org_patterns = [
                        r'([A-Z][a-zA-Z0-9\s]+(?:Corporation|Corp\.?|Limited|Ltd\.?|Inc\.?|LLC|LLP))',
                        r'([A-Z][a-zA-Z0-9\s]+\s+(?:Group|Systems|Technologies|Solutions|Services))'
                    ]
                    
                    for pattern in org_patterns:
                        matches = re.finditer(pattern, sentence)
                        for match in matches:
                            org_name = match.group(1).strip()
                            if org_name and not org_name.lower().startswith('organization'):
                                yield Organization(value=org_name)

                if self.location:
                    # Process the text to find locations
                    for subtree in sentt.subtrees(filter=lambda t: t.label() in ["GPE", "LOCATION"]):
                        location_text = ' '.join([leave[0] for leave in subtree.leaves()])
                        if location_text and not location_text.lower().startswith('location'):
                            yield Location(value=location_text)
                    
                    # Search for locations in the text using commas as separators
                    potential_locations = [loc.strip() for loc in sentence.split(',')]
                    for loc in potential_locations:
                        tokens = nltk.word_tokenize(loc)
                        pos = nltk.pos_tag(tokens)
                        chunk = nltk.ne_chunk(pos, binary=False)
                        for subtree in chunk.subtrees(filter=lambda t: t.label() in ["GPE", "LOCATION"]):
                            location_text = ' '.join([leave[0] for leave in subtree.leaves()])
                            if location_text and not location_text.lower().startswith('location'):
                                yield Location(value=location_text)

        if len(self.keywords) > 0 or self.keyphrase:
            ta = TextAnalysis(body)
            for k in self.keywords:
                # TODO Generate k variations
                k = k.lower()
                if ta.is_keyword_present(k) > 0 or body.lower().find(k) >= 0:
                    yield Keyword(value=k)

            if self.keyphrase:
                for k in ta.extract_top_keyphrases():
                    yield Keyphrase(value=k)

        # TODO Test if the value is None
        # TODO Refactor to iterate
        # TODO "".join() to avoid regex tuples
        if self.phone:
            # TODO Reformat result number
            phones = PHONE_REGEX.findall(body)
            for phone in phones:
                yield Phone(value="".join(phone))

        if self.email:
            emails = EMAIL_REGEX.findall(body)
            for email in emails:
                yield Email(value=email)
                if self.username:
                    yield Username(value=email.split("@")[0])

        if self.btc_wallet:
            btc_wallets = BTC_WALLET_REGEX.findall(body)
            btc_wallets.extend(BTC_WALLET_BECH32_REGEX.findall(body))
            for btc_wallet in btc_wallets:
                if BTC_Wallet.isvalid(address=btc_wallet):
                    yield BTC_Wallet(value=btc_wallet)

        if self.eth_wallet:
            eth_wallets = ETH_WALLET_REGEX.findall(body)
            for eth_wallet in eth_wallets:
                if ETH_Wallet.isvalid(address=eth_wallet):
                    yield ETH_Wallet(value=eth_wallet)

        if self.xmr_wallet:
            xmr_wallets = XMR_WALLET_REGEX.findall(body)
            for xmr_wallet in xmr_wallets:
                if XMR_Wallet.isvalid(address=xmr_wallet):
                    yield XMR_Wallet(value=xmr_wallet)

        if self.zec_wallet:
            zec_wallets = ZEC_WALLET_TRANSPARENT_REGEX.findall(body)
            zec_wallets.extend(ZEC_WALLET_PRIVATE_REGEX.findall(body))
            zec_wallets.extend(ZEC_WALLET_PRIVATE_SAPLING_REGEX.findall(body))
            for zec_wallet in zec_wallets:
                if ZEC_Wallet.isvalid(address=zec_wallet):
                    yield ZEC_Wallet(value=zec_wallet)

        if self.dash_wallet:
            dash_wallets = DASH_WALLET_REGEX.findall(body)
            for dash_wallet in dash_wallets:
                if DASH_Wallet.isvalid(address=dash_wallet):
                    yield DASH_Wallet(value=dash_wallet)

        if self.dot_wallet:
            dot_wallets = DOT_WALLET_REGEX.findall(body)
            for dot_wallet in dot_wallets:
                if DOT_Wallet.isvalid(address=dot_wallet):
                    yield DOT_Wallet(value=dot_wallet)

        if self.xrp_wallet:
            xrp_wallets = XRP_WALLET_REGEX.findall(body)
            for xrp_wallet in xrp_wallets:
                if XRP_Wallet.isvalid(address=xrp_wallet):
                    yield XRP_Wallet(value=xrp_wallet)

        if self.bnb_wallet:
            bnb_wallets = BNB_WALLET_REGEX.findall(body)
            for bnb_wallet in bnb_wallets:
                if BNB_Wallet.isvalid(address=bnb_wallet):
                    yield BNB_Wallet(value=bnb_wallet)

        if self.credit_card:
            card_numbers = re.findall(all_card_regex, body)
            for card_number in card_numbers:
                if Card_Number.isvalid(card_number):
                    companies = []
                    for company, regex in card_regex.items():
                        if re.match(regex, card_number):
                            companies.append(company)
                    yield Card_Number(value=f"Companies=[{','.join(companies)}] Number={card_number}")

        # Add BIN/IIN extraction
        if self.bin_number:
            for bin_candidate in re.findall(bin_regex, body):
                yield Item(value=f"BIN/IIN={bin_candidate}")

        # Add generic CCN extraction
        if self.ccn_number:
            for ccn_candidate in re.findall(ccn_regex, body):
                # Avoid duplicates with card_numbers
                if not (self.credit_card and re.match(all_card_regex, ccn_candidate)):
                    yield Item(value=f"CCN={ccn_candidate}")

        if self.twitter:
            tw_accounts = TW_ACCOUNT_REGEX.findall(body)
            for tw_account in tw_accounts:
                yield TW_Account(value=tw_account)

        if self.i2p:
            i2p_links = self.extract_links(
                body,
                url_format=I2P_HIDDEN_URL,
                domain_format=I2P_HIDDEN_DOMAIN,
                origin=origin,
            )
            for link in i2p_links:
                try:
                    if isinstance(link, bytes):
                        link = link.decode('utf-8')
                    link_item = UUF(link).full_url
                except Exception as e:
                    print(f"[*] Error processing I2P URL: {e}")
                    link_item = link
                yield I2P_URL(value=link_item)

        if self.tor:
            tor_links = self.extract_links(
                body,
                url_format=TOR_HIDDEN_URL,
                domain_format=TOR_HIDDEN_DOMAIN,
                origin=origin,
            )
            for link in tor_links:
                try:
                    # Ensure link is a string before passing to UUF
                    if isinstance(link, bytes):
                        link = link.decode('utf-8')
                    link_item = UUF(link).full_url
                except Exception as e:
                    print(f"[*] Error processing Tor URL: {e}")
                    # If there's an error, just use the original link
                    if isinstance(link, bytes):
                        try:
                            link_item = link.decode('utf-8')
                        except Exception:
                            link_item = str(link)
                    else:
                        link_item = link
                yield Tor_URL(value=link_item)

        if self.freenet:
            freenet_links = re.findall(freenet_hidden_url, body, re.DOTALL)
            for link in freenet_links:
                yield Freenet_URL(value=link)
                
        if self.zeronet:
            # TODO Experimental
            if self.zeronet_ctxt and False:
                if body.find("zeronet") < 0:
                    pass

            zeronet_links = re.findall(zeronet_hidden_url, body, re.DOTALL)
            zeronet_links = extract_elements(zeronet_links)

            for link in zeronet_links:
                yield Zeronet_URL(value=link)

        if self.bitname:
            bitname_links = re.findall(bitname_url, body, re.DOTALL)
            bitname_links = extract_elements(bitname_links)

            for link in bitname_links:
                yield Bitname_URL(value=link)

        if self.pgp:
            pgp_keys = re.findall(pgp_key, body, re.DOTALL)
            for k in pgp_keys:
                yield PGP(value=k)

        if self.ipfs:
            ipfs_links = re.findall(ipfs_url, body, re.DOTALL)
            ipfs_links = extract_elements(ipfs_links)
            for link in ipfs_links:
                yield IPFS_URL(value=link)

        if self.whatsapp:
            whatsapp_links = WHATSAPP_URL_REGEX.findall(body)
            whatsapp_links = extract_elements(whatsapp_links)
            for link in whatsapp_links:
                try:
                    if isinstance(link, bytes):
                        link = link.decode('utf-8')
                    link_item = UUF(link).full_url
                except Exception as e:
                    print(f"[*] Error processing WhatsApp URL: {e}")
                    link_item = link
                yield Whatsapp_URL(value=link_item)

        if self.discord:
            discord_links = DISCORD_URL_REGEX.findall(body)
            discord_links = extract_elements(discord_links)
            for link in discord_links:
                try:
                    if isinstance(link, bytes):
                        link = link.decode('utf-8')
                    link_item = UUF(link).full_url
                except Exception as e:
                    print(f"[*] Error processing Discord URL: {e}")
                    link_item = link
                yield Discord_URL(value=link_item)

        if self.telegram:
            telegram_links = TELEGRAM_URL_REGEX.findall(body)
            telegram_links = extract_elements(telegram_links)
            for link in telegram_links:
                try:
                    if isinstance(link, bytes):
                        link = link.decode('utf-8')
                    link_item = UUF(link).full_url
                except Exception as e:
                    print(f"[*] Error processing Telegram URL: {e}")
                    link_item = link
                yield Telegram_URL(value=link_item)

        if self.skype:
            skype_links = SKYPE_URL_REGEX.findall(body)
            for link in skype_links:
                try:
                    if isinstance(link, bytes):
                        link = link.decode('utf-8')
                    link_item = UUF(link).full_url
                except Exception as e:
                    print(f"[*] Error processing Skype URL: {e}")
                    link_item = link
                yield Skype_URL(value=link_item)

        if self.username:
            usernames = USERNAME_REGEX.findall(body)
            for username in usernames:
                yield Username(value=username)

        if self.paste:
            pastes = PASTE_URL_REGEX.findall(body)
            for pst in pastes:
                yield Paste(value=pst)

        if self.password:
            passwords = PASSWORD_REGEX.findall(body)
            for password in passwords:
                yield Password(value=password)

        if self.base64:
            base64s = BASE64_REGEX.findall(body)
            for b64 in base64s:
                yield Base64(value=b64)

        if self.md5:
            md5s = MD5_REGEX.findall(body)
            for md5 in md5s:
                yield MD5(value=md5)

        if self.sha1:
            sha1s = SHA1_REGEX.findall(body)
            for sha1 in sha1s:
                yield SHA1(value=sha1)

        if self.sha256:
            sha256s = SHA256_REGEX.findall(body)
            for sha256 in sha256s:
                yield SHA256(value=sha256)
        
        if self.tox:
            tox_ids = TOX_ID_REGEX.findall(body)
            for tox_id in tox_ids:
                if Tox_ID.isvalid(tox_id):
                    yield Tox_ID(value=tox_id)
        
        if self.gatc:
            gatc = GA_TRACKING_CODE_REGEX.findall(body)
            for g in gatc:
                if GA_Tracking_Code.isvalid(g):
                    yield GA_Tracking_Code(value=g)

        if self.session_id:
            session_ids = SESSION_ID_REGEX.findall(body)
            for sid in session_ids:
                session_id_value = sid
                if Session_ID.isvalid(session_id_value):
                    yield Session_ID(value=session_id_value)

    def parse(self, body, origin=None, buff_size=20480):

        i = 0

        chunk_size = buff_size // 2

        # print("Chunks", len(body)//chunk_size)
        
        while i * chunk_size <= len(body):

            chunk = body[i * chunk_size: (i + 2) * chunk_size]
            
            chunk_analysis = self._analyze_chunk(chunk, origin=origin)

            for result in chunk_analysis:
                yield result

            i += 1
            # print("Chunk", i)


# import stalker
# s = stalker.Stalker(zeronet=True)
# print([str(x) for x in s.parse('http://abc.bit')])


def main():
    import sys

    parse_file = sys.argv[1]
    s = reStalker(all=True)
    with open(parse_file) as f:
        parser = s.parse(f.read())
    for element in parser:
        print(type(element), element)


if __name__ == "__main__":
    main()
