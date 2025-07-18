from setuptools import setup


with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="restalker",
    version="2.0.8",
    description="Text analyzer package",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://gitlab.com/junquera/stalker",
    author="Javier Junquera Sánchez",
    author_email="javier@junquera.io",
    license="MIT",
    packages=["restalker"],
    install_requires=[
        "based58",
        "bech32ref",
        "bip-utils",
        "bs4",
        "nltk",
        "numpy",
        "monero",
        "rake-nltk",
        "web3",
    ],
    entry_points=dict(console_scripts=["restalker=restalker.restalker:main"]),
)
