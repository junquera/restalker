![doc/img/icon.png](doc/img/icon.png)

# reStalker

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
[![contributions welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dwyl/esta/issues)

IOC and entities extractor.

## Detection

`reStalker` can extract these entities from any binary or text source:

- Phone

- Email

- Digital assets

    - BTC Wallet

    - ETH Wallet

    - XMR Wallet

    - ZEC Wallet

    - DASH Wallet

    - DOT Wallet

    - XRP Wallet

    - BNB Wallet

- TW Account

- Tor URL

- I2P URL

- Freenet URL

- Zeronet URL

- IPFS URL

- Username

- Password

- Base64

- OwnName

- Telegram URL

- Whatsapp URL

- Skype URL

- Paste

- MD5

- SHA1

- SHA256

## Install

Console:

```sh
pip3 install "restalker<3"
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
    print("[*] Darknet IOC found:", element)
```

# Acknowledgements

[Byron Labs](https://byronlabs.io/) is an active supporter of the `reStalker` development.

![](https://gitlab.com/junquera/restalker/-/raw/master/doc/img/byronlabs-300x142.png)
