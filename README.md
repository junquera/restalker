![doc/img/icon.png](doc/img/icon.png)

# reStalker

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dwyl/esta/issues)

IOC and entities extractor.

## Detection

`reStalker` can extract these entities from any binary or text source:

- Base64

- Credentials

    - Username

    - Password

    - Phone

    - Email

    - Own Name

- Digital assets

    - BTC Wallet

    - ETH Wallet

    - XMR Wallet

    - ZEC Wallet

    - DASH Wallet

    - DOT Wallet

    - XRP Wallet

    - BNB Wallet

- Social networks

    - TW / X Account

    - Telegram URL

    - Whatsapp URL

    - Skype URL

    - Tox ID

    - Session ID

- Hashes

    - MD5

    - SHA1

    - SHA256

- Credit Cards

    - Bin Numbers

    - Credit Card Numbers

- URLs

    - Tor URL

    - I2P URL

    - Freenet URL

    - Zeronet URL

    - IPFS URL

- Paste sites

    - justpaste.it

    - pastebin.com

    - pasted.co

    - hastebin.com

    - snipt.org

    - gist.github.com

    - telegra.ph

    - ghostbin.com

## Documentation

You can find further [documentation](https://deepwiki.com/junquera/restalker) here.

## Install

Console:

```sh
pip3 install restalker<3
```

In `requeriments.txt`:

* Production

```
restalker<3
```

* Development

```
git+https://github.com/junquera/restalker.git#egg=restalker
```

## Usage

```python
import restalker

# Define which elements we desire
# for example Tor URLs
s = restalker.reStalker(tor=True, i2p=True)

elements = s.parse(input_text)

for element in elements:
    print(f"[*] Darknet IOC found: {element}")
```

# Acknowledgements

[Byron Labs](https://byronlabs.io/) is an active supporter of the `reStalker` development.

![Byron Labs Logo](doc/img/logo_byronlabs.png)
