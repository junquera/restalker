from .link_extractors import UUF
from urllib.parse import urljoin

from bs4 import BeautifulSoup

import re


class Item():
    def __init__(self, value=None):
        self.value = value

    def __str__(self):
        return self.value


class Phone(Item):
    pass


class Email(Item):
    pass


class BTC_Wallet(Item):
    pass


class ETH_Wallet(Item):
    pass


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

class Paste(Item):
    pass

class MD5(Item):
    pass

class SHA1(Item):
    pass

class SHA256(Item):
    pass



phone_regex = r"(\(?\+[0-9]{1,3}\)? ?-?[0-9]{1,3} ?-?[0-9]{3,5} ?-?[0-9]{4}( ?-?[0-9]{3})? ?(\w{1,10}\s?\d{1,6})?)"

email_regex = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,6})"

btc_wallet_regex = r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})"

eth_wallet_regex = r"0x([0-9a-f]{40})"

tw_account_regex = r"[^a-zA-Z0-9]@([a-zA-Z0-9_]{3,15})"

telegram_url_regex = r'((?:https?\:\/\/)?(?:t\.me|telegram\.me)(?:\/[a-zA-Z0-9_-]+)+)'

whatsapp_url_regex = r'((?:https?\:\/\/)?chat\.whatsapp\.com(?:\/[a-zA-Z0-9_-]+)+)'

skype_url_regex = r'((?:https?\:\/\/)?join\.skype\.com(?:\/[a-zA-Z0-9]+)+)'

username_regex = r"([a-zA-Z0-9\$\.,;_-]{8,20})[^a-zA-Z0-9]"

password_regex = r"(?:[Pp]ass(?:word)?.|[a-zA-Z0-9_-]\:)([a-zA-Z0-9$,;_-]{4,16})"

base64_regex = r"((?:[a-zA-Z0-9\+\/]{4})+(?:[a-zA-Z0-9\+\/]{3}[=]|[a-zA-Z0-9\+\/]{2}[=]{2}))"

own_name_regex = r"([A-Z][a-z]{2,10} [A-Z][a-z]{2,10})"

any_domain = r'(?:[a-z0-9]+\.)*[a-z0-9]+\.?(?:\:[0-9]{2,5})?$'
any_url = r'((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)' % any_domain[:-1]

tor_hidden_domain = r'(?:[a-z0-9]+\.)*(?:[a-z0-9]{16}|[a-z0-9]{56})\.onion(?:\:[0-9]{2,5})?$'
tor_hidden_url = r'((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)' % tor_hidden_domain[:-1]

i2p_hidden_domain = r'(?:[a-z0-9]+\.)+i2p(?:\:[0-9]{2,5})?$'
i2p_hidden_url = r'((?:https?:\/\/)?%s(?:\/[a-zA-Z0-9_-]*)*)' % i2p_hidden_domain[:-1]


freenet_hidden_url = r'((?:(?:http\:\/\/)?(?:(?:localhost|127\.0\.0\.1)\:8888\/))?(?:(?:[a-z]+\:)?[a-zA-Z0-9]+\@[^,]+,[^,]+,[A-Z]+)(?:\/[a-zA-Z0-9_-]+)+)'
'''
Crear sitios de freenet:

http://localhost:8888/freenet:USK@spOnEa2YvAoNfreZPfoy0tVNCzQghLdWaaNM10GEiEM,QRKjyaBkOX5Qw~aEml19WIDaJJo2X3hU9mGz8GcUuKc,AQACAAE/freesite_es/11/
'''

http_regex = r'https?\:\/\/'
localhost_regex = r'(?:localhost|127\.0\.0\.1)'
port_regex = lambda p: r'(?:\:%d)?' % (p)
path_regex = r'(?:\/[a-zA-Z0-9_-]*)*'


bitname_domain_regex = r'(?:[a-zA-Z0-9]+\.)+bit'
zeronet_params=dict(http=http_regex, localhost=localhost_regex, port=port_regex(43110), path=path_regex, bitcoin=btc_wallet_regex, bitname=bitname_domain_regex)
zeronet_hidden_url = r'((?:(?:{http}?{localhost}{port})\/)?(?:{bitcoin}|{bitname})(?:{path}))'.format(**zeronet_params)

pastes = [
    'justpaste.it',
    'pastebin.com',
    'pasted.co',
    'hastebin.com',
    'snipt.org',
    'gist.github.com',
    'ghostbin.com'
]

paste_url_regex = r'((?:https?\:\/\/)?(?:%s)(?:\/[a-zA-Z0-9_-]+)+)' % ("|".join(pastes))

md5_regex = r'[a-f0-9]{32}'
sha1_regex = r'[a-f0-9]{40}'
sha256_regex = r'[a-f0-9]{64}'

class Stalker():

    def __init__(self, phone=False, email=False,
                 btc_wallet=False, eth_wallet=False,
                 tor=False, i2p=False,
                 freenet=False, zeronet=False
                 paste=False, twitter=False,
                 username=False, password=False,
                 base64=False, own_name=False,
                 whatsapp=False, telegram=False, skype=False,
                 md5=False, sha1=False, sha256=False):

        self.phone = phone
        self.email = email
        self.twitter = twitter

        self.btc_wallet = btc_wallet
        self.eth_wallet = eth_wallet

        self.tor = tor
        self.i2p = i2p
        self.freenet = freenet
        self.zeronet = zeronet

        self.paste = paste

        self.username = username
        self.password = password
        self.base64 = base64
        self.own_name = own_name
        self.whatsapp = whatsapp
        self.telegram = telegram
        self.skype = skype

        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256

    def extract_links(self, body, origin=None, url_format=any_url, domain_format=any_domain):

        urls = set()

        for url in re.findall(url_format, body, re.DOTALL):
            try:
                urls.add(UUF(url).rebuild())
            except Exception as e:
                pass

        soup = BeautifulSoup(body, "html.parser")
        if soup:
            links = soup.findAll('a')
            if links:
                for url in links:
                    try:
                        urls.add(UUF(urljoin(origin, url.get('href'))).rebuild())
                    except Exception as e:
                        pass

        for url in urls:
            if url:
                parsed_url = UUF(url)
                # TODO Usar la regex completa en lugar de sólo el dominio?
                if re.match(domain_format, parsed_url.domain, re.DOTALL):
                    yield parsed_url.rebuild()

    def body_text(self, body):
        try:
            # TODO ¿Esto se puede hacer con el response de scrapy?
            soup = BeautifulSoup(body, "lxml")

            for script in soup(["script", "style"]):
                script.extract()    # rip it out

            text = soup.get_text()

            lines = (line.strip() for line in text.splitlines())
            chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
            text = '\n'.join(chunk for chunk in chunks if chunk)
        except Exception as e:
            text = body

        return text

    def parse(self, body, origin=None):

        text = self.body_text(body)

        # TODO Test si el valor es None
        # TODO Refactor para iterar
        # TODO "".join() para evitar tuplas de la regex
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
                    yield Username(value=email.split('@')[0])

        if self.btc_wallet:
            btc_wallets = re.findall(btc_wallet_regex, body)
            for btc_wallet in btc_wallets:
                yield BTC_Wallet(value=btc_wallet)

        if self.eth_wallet:
            eth_wallets = re.findall(eth_wallet_regex, body)
            for eth_wallet in eth_wallets:
                yield ETH_Wallet(value=eth_wallet)

        if self.twitter:
            tw_accounts = re.findall(tw_account_regex, text)
            for tw_account in tw_accounts:
                yield TW_Account(value=tw_account)

        if self.i2p:
            i2p_links = self.extract_links(body,
                                           url_format=i2p_hidden_url,
                                           domain_format=i2p_hidden_domain,
                                           origin=origin)
            for link in i2p_links:
                try:
                    link_item = UUF(link).full_url
                except Exception as e:
                    link_item = link
                yield I2P_URL(value=link_item)

        if self.tor:
            tor_links = self.extract_links(body,
                                           url_format=tor_hidden_url,
                                           domain_format=tor_hidden_domain,
                                           origin=origin)
            for link in tor_links:
                try:
                    link_item = UUF(link).full_url
                except Exception as e:
                    link_item = link
                yield Tor_URL(value=link_item)

        if self.freenet:
            freenet_links = self.extract_links(body,
                                               url_format=freenet_hidden_url,
                                               origin=origin)
            for link in freenet_links:
                yield Freenet_URL(value=link)

        if self.zeronet:
            zeronet_links = self.extract_links(body,
                                               url_format=zeronet_hidden_url,
                                               origin=origin)
            for link in zeronet_links:
                yield Zeronet_URL(value=link)

        if self.whatsapp:
            whatsapp_links = re.findall(whatsapp_url_regex, body)
            for link in whatsapp_links:
                try:
                    link_item = UUF(link).full_url
                except Exception as e:
                    link_item = link
                yield Whatsapp_URL(value=link_item)

        if self.telegram:
            telegram_links = re.findall(telegram_url_regex, body)
            for link in telegram_links:
                try:
                    link_item = UUF(link).full_url
                except Exception as e:
                    link_item = link
                yield Telegram_URL(value=link_item)

        if self.skype:
            skype_links = re.findall(skype_url_regex, body)
            for link in skype_links:
                try:
                    link_item = UUF(link).full_url
                except Exception as e:
                    link_item = link
                yield Skype_URL(value=link_item)

        if self.username:
            usernames = re.findall(username_regex, text)
            for username in usernames:
                yield Username(value=username)

        if self.paste:
            pastes = re.findall(paste_url_regex, text)
            for pst in pastes:
                yield Paste(value=pst)

        if self.password:
            passwords = re.findall(password_regex, text)
            for password in passwords:
                yield Password(value=password)

        if self.base64:
            base64s = re.findall(base64_regex, body)
            for b64 in base64s:
                yield Base64(value=b64)

        if self.own_name:
            own_names = re.findall(own_name_regex, text)
            for own_name in own_names:
                yield OwnName(value=own_name)

        if self.md5:
            md5s = re.findall(md5_regex, text)
            for md5 in md5s:
                yield MD5(value=md5)

        if self.sha1:
            sha1s = re.findall(sha1_regex, text)
            for sha1 in sha1s:
                yield SHA1(value=sha1)

        if self.sha256:
            sha256s = re.findall(sha256_regex, text)
            for sha256 in sha256s:
                yield SHA256(value=sha256)
