![doc/img/icon.png](https://gitlab.com/junquera/restalker/-/raw/master/doc/img/icon.png)

# reStalker

[![Total alerts](https://img.shields.io/lgtm/alerts/g/junquera/stalker.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/junquera/stalker/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/junquera/stalker.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/junquera/stalker/context:python)

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

In `requeriments.txt`:

```
git+https://gitlab.com/junquera/stalker.git#egg=stalker
```

## Usage

```python
import stalker

# Define which elements we desire
# for example Tor URLs
s = stalker.Stalker(tor=True, i2p=True)

elements = s.parse(input_text)

for element in elements:
    print("[*] Darknet IOC found:", element)
```

# Acknowledgements

[Byron Labs](https://byronlabs.io/) is an active supporter of the `reStalker` development.

![](https://gitlab.com/junquera/restalker/-/raw/master/doc/img/byronlabs-300x142.png)
