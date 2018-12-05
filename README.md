
![doc/img/icon.png](doc/img/icon.png)

# Stalker

[![Total alerts](https://img.shields.io/lgtm/alerts/g/junquera/stalker.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/junquera/stalker/alerts/)
[![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/junquera/stalker.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/junquera/stalker/context:python)

## Detection

- Phone

- Email

- BTC Wallet

- ETH Wallet

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
s = stalker.Stalker(tor=True)

elements = s.parse(input_text)
```
