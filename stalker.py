from crawler.link_extractors import UUF
from urllib.parse import urljoin

from bs4 import BeautifulSoup

import re


class Item():
    def __init__(self, value=None):
        self.value = value


class Phone(Item):
    pass


class Email(Item):
    pass


class BTC_Wallet(Item):
    pass


class TW_Account(Item):
    pass


class Tor_URL(Item):
    pass


class I2P_URL(Item):
    pass


class Freenet_URL(Item):
    pass


class ZeroNet_URL(Item):
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



phone_regex = r"(\(?\+[0-9]{1,3}\)? ?-?[0-9]{1,3} ?-?[0-9]{3,5} ?-?[0-9]{4}( ?-?[0-9]{3})? ?(\w{1,10}\s?\d{1,6})?)"

email_regex = r"([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]{2,6})"

btc_wallet_regex = r"([13][a-km-zA-HJ-NP-Z1-9]{25,34})"

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


freenet_hidden_url = r'((?:(?:http\:\/\/)?(?:localhost\:8888\/))?(?:(?:[a-z]+\:)?[a-zA-Z0-9]+\@[^,]+,[^,]+,[A-Z]+)(?:\/[a-zA-Z0-9_-]+)+)'

zeronet_hidden_url = r'((?:(?:http\:\/\/)?(?:(?:localhost|127\.0\.0\.1)\:43110\/))?(?:(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34})|(?:(?:[a-zA-Z0-9]+\.)+bit))(?:\/[a-zA-Z0-9_-]*)*)'

'''
Crear sitios de freenet:

http://localhost:8888/freenet:USK@spOnEa2YvAoNfreZPfoy0tVNCzQghLdWaaNM10GEiEM,QRKjyaBkOX5Qw~aEml19WIDaJJo2X3hU9mGz8GcUuKc,AQACAAE/freesite_es/11/
'''

class Stalker():

    def __init__(self, phone=False, email=False, btc_wallet=False,
                 twitter=False, tor=False, i2p=False,
                 freenet=False, zeronet=False, username=False,
                 password=False, base64=False, own_name=False,
                 whatsapp=False, telegram=False, skype=False):
        self.phone = phone
        self.email = email
        self.btc_wallet = btc_wallet
        self.twitter = twitter

        self.tor = tor
        self.i2p = i2p
        self.freenet = freenet
        self.zeronet = zeronet

        self.username = username
        self.password = password
        self.base64 = base64
        self.own_name = own_name
        self.whatsapp = whatsapp
        self.telegram = telegram
        self.skype = skype

    def extract_links(self, body, origin=None, url_format=any_url, domain_format=any_domain):

        urls = set()

        for url in re.findall(url_format, body, re.DOTALL):
            try:
                urls.add(UUF(url).rebuild())
            except Exception as e:
                pass

        soup = BeautifulSoup(body, "lxml")
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
