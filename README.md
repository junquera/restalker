# 🕵️ reStalker

![reStalker Logo](https://github.com/junquera/restalker/blob/develop/doc/img/icon.png)

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

- **Base64** encoded data (`base64=True`)
- **Username** patterns (`username=True`)
- **Password** patterns (`password=True`)
- **Phone** numbers (`phone=True`)
- **Email** addresses (`email=True`)
- **Personal names** (`own_name=True`)
- **PGP** keys (`pgp=True`)

### 🗺️ Location & Organization

- **Location** information (`location=True`)
- **Organization** names (`organization=True`)
- **Keyphrases** (`keyphrase=True`)
- **Keywords** (`keywords=["keyword1", "keyword2"]`)

### 📊 Analytics & Tracking

- **Google Analytics** tracking codes (`gatc=True`)

### 💰 Digital Assets & Cryptocurrencies

- **BTC** (Bitcoin) wallet addresses (`btc_wallet=True`)
- **ETH** (Ethereum) wallet addresses (`eth_wallet=True`)
- **XMR** (Monero) wallet addresses (`xmr_wallet=True`)
- **ZEC** (Zcash) wallet addresses (`zec_wallet=True`)
- **DASH** wallet addresses (`dash_wallet=True`)
- **DOT** (Polkadot) wallet addresses (`dot_wallet=True`)
- **XRP** (Ripple) wallet addresses (`xrp_wallet=True`)
- **BNB** (Binance) wallet addresses (`bnb_wallet=True`)

### 📱 Social Networks & Communication

- **Twitter/X** account handles (`twitter=True`)
- **Telegram** URLs (`telegram=True`)
- **WhatsApp** URLs (`whatsapp=True`)
- **Discord** URLs (`discord=True`)
- **Skype** URLs (`skype=True`)
- **Tox ID** identifiers (`tox=True`)
- **Session ID** identifiers (`session_id=True`)

### 🔐 Cryptographic Hashes

- **MD5** hash values (`md5=True`)
- **SHA1** hash values (`sha1=True`)
- **SHA256** hash values (`sha256=True`)

### 💳 Financial Information

- **BIN** (Bank Identification Numbers) (`bin_number=True`)
- **Credit Card** numbers (`credit_card=True`)
- **CCN** (Credit Card Numbers - generic) (`ccn_number=True`)

### 🌐 Dark Web & Alternative Networks

- **Tor** (.onion) URLs (`tor=True`)
- **I2P** URLs (`i2p=True`)
- **Freenet** URLs (`freenet=True`)
- **ZeroNet** URLs (`zeronet=True`)
- **BitName** URLs (`bitname=True`)
- **IPFS** URLs (`ipfs=True`)

### 📋 Paste Sites & Code Sharing

- **justpaste.it** links (`paste=True`)
- **pastebin.com** links (`paste=True`)
- **pasted.co** links (`paste=True`)
- **hastebin.com** links (`paste=True`)
- **snipt.org** links (`paste=True`)
- **gist.github.com** links (`paste=True`)
- **telegra.ph** links (`paste=True`)
- **ghostbin.com** links (`paste=True`)

---

## 📦 Installation

### 🎯 Quick Start

**CPU-only (Default, Recommended for Most Users):**
```bash
pip install restalker
```

**Or with Poetry:**
```bash
poetry add restalker
```

---

### 🚀 GPU Acceleration (Optional)

reStalker supports GPU acceleration for significantly faster entity extraction using GLiNER. Choose the appropriate installation method based on your hardware:

#### 🔍 Automatic Detection (Recommended)

```bash
# Clone or navigate to the repository
git clone https://github.com/junquera/restalker.git
cd restalker

# Detect your GPU hardware
python scripts/detect_gpu.py

# Follow the recommended installation command shown
```

#### 🎮 Manual GPU Installation

**NVIDIA GPU (CUDA 11.8+):**

```bash
# Using Poetry
poetry install --extras gpu

# Using pip with setup.py
pip install -e .[gpu]

# Using requirements file
pip install -r requirements-gpu-cuda.txt
```

**AMD GPU (ROCm 5.x+, Linux only):**

```bash
# First, install ROCm: https://rocm.docs.amd.com/

# Using Poetry
poetry install --extras amd-gpu

# Using pip with setup.py
pip install -e .[amd-gpu]

# Using requirements file
pip install -r requirements-gpu-rocm.txt
```

**CPU-only (Explicit):**

```bash
# Using Poetry
poetry install

# Using pip with requirements file
pip install -r requirements.txt
```

#### 💾 Disk Space & Performance

| Installation | Disk Space | Performance vs CPU | Best For |
|--------------|------------|-------------------|----------|
| **CPU-only** | ~500 MB | Baseline (1x) | Most users, portable systems |
| **NVIDIA GPU** | ~3.2 GB | 5-10x faster | Systems with NVIDIA GPUs |
| **AMD GPU** | ~3.5 GB | 3-7x faster | Linux systems with AMD GPUs |

#### ✅ Verify GPU Installation

After installing with GPU support, verify it's working:

```python
import torch
print(f"CUDA available: {torch.cuda.is_available()}")
print(f"Device: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU'}")
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

![Byron Labs Logo](https://github.com/junquera/restalker/blob/develop/doc/img/logo_byronlabs.png)
