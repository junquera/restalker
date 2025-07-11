# 🕵️ reStalker

![reStalker Logo](doc/img/icon.png)

**IOC and Entities Extractor**

![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=for-the-badge)](https://github.com/dwyl/esta/issues)
[![Documentation](https://img.shields.io/badge/docs-available-blue.svg?style=for-the-badge)](https://deepwiki.com/junquera/restalker)

A powerful Python library for extracting Indicators of Compromise (IOCs) and various entities from binary or text sources.

---

## 📋 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [🎯 Detection Capabilities](#-detection-capabilities)
- [📦 Installation](#-installation)
- [💻 Usage Examples](#-usage-examples)
- [📖 Documentation](#-documentation)
- [🤝 Contributing](#-contributing)
- [🙏 Acknowledgements](#-acknowledgements)

---

## 🚀 Quick Start

```python
import restalker

# Define which elements we desire (e.g., Tor URLs)
s = restalker.reStalker(tor=True, i2p=True)
elements = s.parse(input_text)

for element in elements:
    print(f"[*] Darknet IOC found: {element}")
```

---

## 🎯 Detection Capabilities

`reStalker` can extract these entities from any binary or text source:

### 🔐 Credentials & Identity

- **Base64** encoded data `(base64=True)`
- **Username** patterns `(username=True)`
- **Password** patterns `(password=True)`
- **Phone** numbers `(phone_number=True)`
- **Email** addresses `(email_address=True)`
- **Personal names** `(person_name=True)`

### 💰 Digital Assets & Cryptocurrencies

- **BTC** (Bitcoin) wallet addresses `(bitcoin_address=True)`
- **ETH** (Ethereum) wallet addresses `(ethereum_address=True)`
- **XMR** (Monero) wallet addresses `(monero_address=True)`
- **ZEC** (Zcash) wallet addresses `(zcash_address=True)`
- **DASH** wallet addresses `(dash_address=True)`
- **DOT** (Polkadot) wallet addresses `(polkadot_address=True)`
- **XRP** (Ripple) wallet addresses `(ripple_address=True)`
- **BNB** (Binance) wallet addresses `(binance_address=True)`

### 📱 Social Networks & Communication

- **Twitter/X** account handles `(twitter_account=True)`
- **Telegram** URLs `(telegram_url=True)`
- **WhatsApp** URLs `(whatsapp_url=True)`
- **Skype** URLs `(skype_url=True)`
- **Tox ID** identifiers `(tox_id=True)`
- **Session ID** identifiers `(session_id=True)`

### 🔐 Cryptographic Hashes

- **MD5** hash values `(md5_hash=True)`
- **SHA1** hash values `(sha1_hash=True)`
- **SHA256** hash values `(sha256_hash=True)`

### 💳 Financial Information

- **BIN** (Bank Identification Numbers) `(bin_number=True)`
- **Credit Card** numbers `(credit_card_number=True)`

### 🌐 Dark Web & Alternative Networks

- **Tor** (.onion) URLs `(onion_address=True)`
- **I2P** URLs `(i2p_address=True)`
- **Freenet** URLs `(freenet_address=True)`
- **ZeroNet** URLs `(zeronet_address=True)`
- **IPFS** URLs `(ipfs_address=True)`

### 📋 Paste Sites & Code Sharing `(paste_url=True)`

- **justpaste.it** links
- **pastebin.com** links
- **pasted.co** links
- **hastebin.com** links
- **snipt.org** links
- **gist.github.com** links
- **telegra.ph** links
- **ghostbin.com** links

---

## 📦 Installation

### 🚀 Quick Install

```bash
pip3 install restalker
```

### 📄 Requirements File

**Production:**

```txt
restalker<3
```

**Development:**

```txt
git+https://github.com/junquera/restalker.git#egg=restalker
```

---

## 💻 Usage Examples

### Basic Usage

```python
import restalker

# Create a reStalker instance with specific detection types
stalker = restalker.reStalker(tor=True, i2p=True, btc=True)

# Parse input text for IOCs
elements = stalker.parse(input_text)

# Process the results
for element in elements:
    print(f"[*] IOC found: {element}")
```

### Advanced Configuration

```python
import restalker

# Enable multiple detection types
stalker = restalker.reStalker(
    tor=True,           # Tor .onion URLs
    i2p=True,           # I2P URLs
    btc=True,           # Bitcoin addresses
    eth=True,           # Ethereum addresses
    email=True,         # Email addresses
    telegram=True,      # Telegram URLs
    base64=True         # Base64 encoded data
)

# Process your data
with open('data.txt', 'r') as f:
    content = f.read()
    
results = stalker.parse(content)

# Categorize results
for result in results:
    print(f"Type: {result.type}, Value: {result.value}")
```

---

## 📖 Documentation

For comprehensive documentation, examples, and API reference, visit our [documentation site](https://deepwiki.com/junquera/restalker).

---

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

## 🙏 Acknowledgements

[Byron Labs](https://byronlabs.io/) is an active supporter of the `reStalker` development.

![Byron Labs Logo](doc/img/logo_byronlabs.png)
