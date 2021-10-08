from setuptools import setup

readme='''

![doc/img/icon.png](doc/img/icon.png)

# reStalker

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

- Keywords

And more.

## Install

In `requeriments.txt`:

```
git+https://gitlab.com/junquera/stalker.git#egg=stalker
```

## Usage

```python
import restalker

# Define which elements we desire
# for example Tor URLs
s = restalker.reStalker(tor=True)

elements = s.parse(input_text)
```
'''

setup(name='restalker',
      version='1.0.0.0',
      description=readme,
      url='https://gitlab.com/junquera/stalker',
      author='Javier Junquera Sánchez',
      author_email='javier@junquera.io',
      license='MIT',
      packages=['restalker'],
      install_requires=[
        'bs4',
        'nltk',
        'numpy',
        'nltk',
        'rake-nltk'
      ],
      entry_points=dict(
        console_scripts= [
            'restalker=restalker.restalker:main'
        ]
      ),
      zip_safe=False
)


# TODO Post-install script:
# import nltk
# nltk.download('stopwords')
# nltk.download('punkt')

