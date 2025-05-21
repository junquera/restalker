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
            ret = Web3.isAddress(address)
        except:
            ret = False
        return ret



class XMR_Wallet(Item):
    @staticmethod
    def isvalid(address: str) -> bool:
        ret = False
        try:
            ret = xmr_address(address) is not None
        finally:
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

number_regex = r"[0-9]+"

alnum_join = r"[a-zA-Z0-9\-\~]+"

file_name = r"(?:[a-zA-Z0-9\_]+\.)+\.[a-zA-Z0-9]{2,4}"

phone_regex = r"(\(?\+[0-9]{1,3}\)? ?-?[0-9]{1,3} ?-?[0-9]{3,5} ?-?[0-9]{4}( ?-?[0-9]{3})? ?(\w{1,10}\s?\d{1,6})?)"

email_regex = r"([a-zA-Z0-9_.+-]+@(?:[a-zA-Z0-9-]+\.)+(?:[0-9][a-zA-Z0-9]{0,4}[a-zA-Z]|[0-9][a-zA-Z][a-zA-Z0-9]{0,4}|[a-zA-Z][a-zA-Z0-9]{1,5}))"

btc_wallet_regex = r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})"

btc_wallet_bech32_regex = r"(bc1[qp][qpzry9x8gf2tvdw0s3jn54khce6mua7l]{38,58})"

eth_wallet_regex = r"(0x[0-9a-fA-F]{40})"

xmr_wallet_regex = r"([48][a-km-zA-HJ-NP-Z1-9]{94,105})"

zec_wallet_transparent_regex = r"(t[13][a-km-zA-HJ-NP-Z1-9]{33})"

zec_wallet_private_regex = r"(zc[a-km-zA-HJ-NP-Z1-9]{93})"

zec_wallet_private_sapling_regex = r"(zs1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{75})"

dash_wallet_regex = r"(X[a-km-zA-HJ-NP-Z1-9]{33})"

dot_wallet_regex = r"(1[a-km-zA-HJ-NP-Z1-9]{46,47})"

xrp_wallet_regex = (
    r"([rX][rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{26,46})"
)

bnb_wallet_regex = r"(bnb[a-zA-Z0-9]{39})"

bitname_domain_regex = r"(?:[a-zA-Z0-9]+\.)+bit"

tw_account_regex = r"[^a-zA-Z0-9]@([a-zA-Z0-9_]{3,15})"

telegram_url_regex = re.compile(
    r"((?:https?:\/\/)?(?:t\.me|telegram\.me|teleg\.one|tgclick\.com)(?:\/[a-zA-Z0-9_-]+)+)|"
    r"((?:tg:\/\/)(?:[a-zA-Z0-9_-]+\?[a-zA-Z0-9_-]+=[a-zA-Z0-9_-]+)+)"
)

whatsapp_url_regex = r"((?:https?\:\/\/)?chat\.whatsapp\.com(?:\/[a-zA-Z0-9_-]+)+)"

discord_url_regex = (
    r"((?:https?\:\/\/)?discord(?:app)?\.(?:gg|com|net)(?:\/[a-zA-Z0-9_-]+)+)"
)

skype_url_regex = r"((?:https?\:\/\/)?join\.skype\.com(?:\/[a-zA-Z0-9]+)+)"

username_regex = r"([a-zA-Z0-9\$\.,;_-]{8,20})[^a-zA-Z0-9]"

password_regex = r"(?:[Pp]ass(?:word)?.|[a-zA-Z0-9_-]\:)([a-zA-Z0-9$,;_-]{4,16})"

base64_regex = (
    r"((?:[a-zA-Z0-9\+\/]{4})+(?:[a-zA-Z0-9\+\/]{3}[=]|[a-zA-Z0-9\+\/]{2}[=]{2}))"
)

own_name_regex = r"([A-Z][a-z]{2,10} [A-Z][a-z]{2,10})"

domain_regex = r"(?:[a-z0-9]+\.){0,4}[a-z0-9]+\.?(?:\:[0-9]{2,5})?$"
any_url = r"((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)" % domain_regex[:-1]

tor_hidden_domain = (
    r"(?:[a-z0-9]+\.){0,4}(?:[a-z0-9]{16}|[a-z0-9]{56})\.onion(?:\:[0-9]{2,5})?$"
)
tor_hidden_url = r"((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)" % tor_hidden_domain[:-1]

i2p_hidden_domain = r"(?:[a-z0-9]+\.){1,5}i2p(?:\:[0-9]{2,5})?$"
i2p_hidden_url = r"((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)" % i2p_hidden_domain[:-1]

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
    user_selected_name="[a-zA-Z0-9\_]+",
    version=number_regex,
    file_name=file_name,
)

freenet_keys = dict(
    chk="CHK@{file_hash},{decryption_key},{crypto_settings}",
    ssk="SSK@{public_key},{decryption_key},{crypto_settings}\/{user_selected_name}\-{version}",
    usk="USK@{public_key},{decryption_key},{crypto_settings}\/{user_selected_name}\/{version}",
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
# TODO Evitar len44 (hay problemas con las llaves para formatear después domain)
ipfs_hash = r"(?:ipfs\/Qm[a-zA-Z0-9]{len44}|ipns\/{domain})".format(
    **dict(len44="{44}", domain=domain_regex)
)
ipfs_params = dict(
    ipfs_hash=ipfs_hash,
    http=http_regex,
    localhost=localhost_regex,
    port=port_regex(8080),
    path=path_regex,
)
ipfs_url = r"((?:{http}?{localhost}{port}(?:\/)?){ipfs_hash}{path})".format(
    **ipfs_params
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

paste_url_regex = r"((?:https?\:\/\/)?(?:%s)(?:\/[a-zA-Z0-9_-]+)+)" % ("|".join(pastes))

md5_regex = r"[a-f0-9]{32}"
sha1_regex = r"[a-f0-9]{40}"
sha256_regex = r"[a-f0-9]{64}"


# Method for avoid lists of lists
def extract_elements(x):
    if type(x) in [tuple, list, set]:
        result = list()
        for piece in x:
            for element in extract_elements(piece):
                if element != "":
                    result.append(element)
        return set(result)
    else:
        return [x]


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

    def add_keyword(self, keyword):
        self.keywords.append(keyword)

    def remove_keyword(self, keyword):
        while keyword in self.keywords:
            self.keywords.remove(keyword)

    def extract_links(self, body, origin=None, url_format=any_url, domain_format=domain_regex):
        urls = set()

        def add_url_safely(url_str):
            """Helper function to safely add URLs to the set"""
            try:
                if url_str and isinstance(url_str, str):
                    cleaned_url = UUF(url_str).rebuild()
                    if cleaned_url:
                        urls.add(cleaned_url)
            except (ValueError, AttributeError) as e:
                print(f"[*] Error processing URL {url_str}: {e}")
            except Exception as e:
                print(f"[*] Unexpected error with URL {url_str}: {e}")

        # Process URLs found with regex
        for url in re.findall(url_format, body, re.DOTALL):
            add_url_safely(url)

        try:
            # soup = BeautifulSoup(body, "html.parser")
            soup = BeautifulSoup(body, "lxml")
            if soup:
                links = soup.findAll("a")
                if links:
                    for url in links:
                        try:
                            urls.add(UUF(urljoin(origin, url.get("href"))).rebuild())
                        except AttributeError:
                            print("[*] AttributeError: Invalid attribute in URL")
                        except ValueError:
                            print("[*] ValueError: Invalid URL format")
                        except Exception as e:
                            print(f"[*] Unexpected error: {e}")
        except TypeError:
            print("[*] TypeError: Invalid input type for BeautifulSoup")
        except Exception as e:
            print(f"[*] Error with HTML parsing: {e}")

        for url in urls:
            if url:
                parsed_url = UUF(url)
                # TODO Use complete regex instead of just the domain?
                if re.match(domain_format, parsed_url.domain, re.DOTALL):
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
            phones = re.findall(phone_regex, body)
            for phone in phones:
                yield Phone(value="".join(phone))

        if self.email:
            emails = re.findall(email_regex, body)
            for email in emails:
                yield Email(value=email)
                if self.username:
                    yield Username(value=email.split("@")[0])

        if self.btc_wallet:
            btc_wallets = re.findall(btc_wallet_regex, body)
            btc_wallets.extend(re.findall(btc_wallet_bech32_regex, body))
            for btc_wallet in btc_wallets:
                if BTC_Wallet.isvalid(address=btc_wallet):
                    yield BTC_Wallet(value=btc_wallet)

        if self.eth_wallet:
            eth_wallets = re.findall(eth_wallet_regex, body)
            for eth_wallet in eth_wallets:
                if ETH_Wallet.isvalid(address=eth_wallet):
                    yield ETH_Wallet(value=eth_wallet)

        if self.xmr_wallet:
            xmr_wallets = re.findall(xmr_wallet_regex, body)
            for xmr_wallet in xmr_wallets:
                if XMR_Wallet.isvalid(address=xmr_wallet):
                    yield XMR_Wallet(value=xmr_wallet)

        if self.zec_wallet:
            zec_wallets = re.findall(zec_wallet_transparent_regex, body)
            zec_wallets.extend(re.findall(zec_wallet_private_regex, body))
            zec_wallets.extend(re.findall(zec_wallet_private_sapling_regex, body))
            for zec_wallet in zec_wallets:
                if ZEC_Wallet.isvalid(address=zec_wallet):
                    yield ZEC_Wallet(value=zec_wallet)

        if self.dash_wallet:
            dash_wallets = re.findall(dash_wallet_regex, body)
            for dash_wallet in dash_wallets:
                if DASH_Wallet.isvalid(address=dash_wallet):
                    yield DASH_Wallet(value=dash_wallet)

        if self.dot_wallet:
            dot_wallets = re.findall(dot_wallet_regex, body)
            for dot_wallet in dot_wallets:
                if DOT_Wallet.isvalid(address=dot_wallet):
                    yield DOT_Wallet(value=dot_wallet)

        if self.xrp_wallet:
            xrp_wallets = re.findall(xrp_wallet_regex, body)
            for xrp_wallet in xrp_wallets:
                if XRP_Wallet.isvalid(address=xrp_wallet):
                    yield XRP_Wallet(value=xrp_wallet)

        if self.bnb_wallet:
            bnb_wallets = re.findall(bnb_wallet_regex, body)
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

        if self.twitter:
            tw_accounts = re.findall(tw_account_regex, body)
            for tw_account in tw_accounts:
                yield TW_Account(value=tw_account)

        if self.i2p:
            i2p_links = self.extract_links(
                body,
                url_format=i2p_hidden_url,
                domain_format=i2p_hidden_domain,
                origin=origin,
            )
            for link in i2p_links:
                try:
                    link_item = UUF(link).full_url
                except Exception:
                    link_item = link
                yield I2P_URL(value=link_item)

        if self.tor:
            tor_links = self.extract_links(
                body,
                url_format=tor_hidden_url,
                domain_format=tor_hidden_domain,
                origin=origin,
            )
            for link in tor_links:
                try:
                    link_item = UUF(link).full_url
                except Exception:
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
            whatsapp_links = re.findall(whatsapp_url_regex, body)
            whatsapp_links = extract_elements(whatsapp_links)
            for link in whatsapp_links:
                try:
                    link_item = UUF(link).full_url
                except Exception:
                    link_item = link
                yield Whatsapp_URL(value=link_item)

        if self.discord:
            discord_links = re.findall(discord_url_regex, body)
            discord_links = extract_elements(discord_links)
            for link in discord_links:
                try:
                    link_item = UUF(link).full_url
                except Exception:
                    link_item = link
                yield Discord_URL(value=link_item)

        if self.telegram:
            telegram_links = re.findall(telegram_url_regex, body)
            telegram_links = extract_elements(telegram_links)
            for link in telegram_links:
                try:
                    link_item = UUF(link).full_url
                except Exception:
                    link_item = link
                yield Telegram_URL(value=link_item)

        if self.skype:
            skype_links = re.findall(skype_url_regex, body)
            for link in skype_links:
                try:
                    link_item = UUF(link).full_url
                except Exception:
                    link_item = link
                yield Skype_URL(value=link_item)

        if self.username:
            usernames = re.findall(username_regex, body)
            for username in usernames:
                yield Username(value=username)

        if self.paste:
            pastes = re.findall(paste_url_regex, body)
            for pst in pastes:
                yield Paste(value=pst)

        if self.password:
            passwords = re.findall(password_regex, body)
            for password in passwords:
                yield Password(value=password)

        if self.base64:
            base64s = re.findall(base64_regex, body)
            for b64 in base64s:
                yield Base64(value=b64)

        if self.md5:
            md5s = re.findall(md5_regex, body)
            for md5 in md5s:
                yield MD5(value=md5)

        if self.sha1:
            sha1s = re.findall(sha1_regex, body)
            for sha1 in sha1s:
                yield SHA1(value=sha1)

        if self.sha256:
            sha256s = re.findall(sha256_regex, body)
            for sha256_hash in sha256s:
                yield SHA256(value=sha256_hash)

        if self.gatc:
            gatc = re.findall(ga_tracking_code_regex, body)
            for g in gatc:
                if GA_Tracking_Code.isvalid(g):
                    yield GA_Tracking_Code(value=g)

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
