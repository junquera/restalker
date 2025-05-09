import pytest
import nltk

"""  README

For testing is required to download some NLTK resources. Run the following command in your terminal:

python3 -c "import nltk; nltk.download('maxent_ne_chunker'); nltk.download('words'); nltk.download('averaged_perceptron_tagger'); nltk.download('maxent_ne_chunker_tab'); nltk.download('punkt'); nltk.download('stopwords')"
"""

from restalker import (
    reStalker, Item, BTC_Wallet, ETH_Wallet, XMR_Wallet,ZEC_Wallet, 
    DASH_Wallet, DOT_Wallet, XRP_Wallet, BNB_Wallet,
    Email, Phone, PGP, GA_Tracking_Code, Tor_URL, I2P_URL,
    IPFS_URL, Base64, Username, Password, Zeronet_URL, Bitname_URL,
    Paste, TW_Account, Location, Organization, Keyphrase,
    OwnName, Whatsapp_URL, Discord_URL, Telegram_URL, Skype_URL, MD5, SHA1, SHA256
)

@pytest.fixture
def sample_crypto_data():
    return """
    BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    ETH: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
    XMR: 888tNkZrPN6JsEgekjMnABU4TBzc2Dt29EPAvkRxbANsAnjyPbb3Y7Rfg5Rm9qL5Hti4UzEO deIfoABLYFfQPlFmhqc2tYS
    """

@pytest.fixture
def sample_communication_data():
    return """
    Email: test@example.com
    Phone: +1-555-123-4567
    Username: test_user_123
    # Basic pass: format
    pass:myP4ssw0rd
    Pass:Secr3t123
    
    # Full password: format
    password:TestP4ss
    Password:Secr3t456
    
    # Custom prefixes
    admin:Adm1n123
    user_1:MyPwd123
    p:Test_123
    
    # With special chars
    pass:my$pwd,123
    password:test;456
    user:pwd_2023

    # With spaces
    # Basic pass: format
    pass: myP4ssw0rd
    Pass: Secr3t123
    
    # Full password: format
    password: TestP4ss
    Password: Secr3t456
    
    # Custom prefixes
    admin: Adm1n123
    user_1: MyPwd123
    p: Test_123
    
    # With special chars
    pass: my$pwd,123
    password: test;456
    user: pwd_2023
    """

@pytest.fixture
def sample_url_data():
    return """
    Tor: http://abcdefghijklmnop.onion
    I2P: http://example.i2p
    IPFS: ipfs://QmW2WQi7j6c7UgJTarActp7tDNikE4B2qXtFCfLPdsgaTQ
    """

@pytest.fixture
def sample_pgp_data():
    return """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: Test 1.0

mQINBGJ7No4BEACqn4EZhMkVu7YE9Z9Sp+Y0iAqnKpLHDJuWHHC6cEGAaIX2VFEG
jxKFzyBcPA==
-----END PGP PUBLIC KEY BLOCK-----"""

@pytest.fixture
def sample_ransom_note():
    return """
    Note:
    If you are reading this text, it means, we've hacked your corporate network.
    Now all your data is encrypted with very serious and powerful algorithms (AES256 and RSA-4,096).
    These algorithms now in use in military intelligence, NSA and CIA.
    Contact emails:
    MckinnisKamariyah91@mail.com
    ThomassenVallen1999@mail.com
    """

@pytest.fixture
def sample_ga_tracking_data():
    return """
    <script async src="https://www.googletagmanager.com/gtag/js?id=UA-12345678-9"></script>
    <script>
      window.dataLayer = window.dataLayer || [];
      function gtag(){dataLayer.push(arguments);}
      gtag('js', new Date());
      gtag('config', 'UA-12345678-9');
    </script>
    <script async src="https://www.googletagmanager.com/gtag/js?id=G-9876543210"></script>
    """

@pytest.fixture
def sample_bitcoin_addresses():
    return """
    1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX
    1PYzcz53HxXCFMKygNAsSdHXuhCx6ec2Y5
    129NVRj7RxBpZsSzbmhAgsZZ1AidWuF828
    1BcsJid3oVmBSVF4tdQJEEHfkcnFLj6fjv
    """

@pytest.fixture
def sample_eth_addresses():
    return """
    0x12ae66cdc592e10b60f9097a7b0d3c59fce29876
    0x12AE66CDc592e10B60f9097a7b0D3C59fce29876
    0x111111111111111111111aaaaaaaaaaaaaaaaaaa
    0x111111111111111111111AAAAAAAAAAAAAAAAAAA
    """

@pytest.fixture
def sample_monero_addresses():
    return """
    4473m2PotByhryknyafx5FPbojXqoQRS5BciBvw78jkffWTtgzynQqNZRY5XyxgbimJotUSkwYGZ9f2aYjZYXvvbVoeG3Ft
    4HMcpBpe4ddJEEnFKUJHAYhGxkeTRH82sf36giEp9AcNfDBfkAtRLX7A6rZz18bbNHPNV7ex6WYbMN3aKisFRJZ8M7yKhzQhKW3ECCLWQw
    84LooD7i35SFppgf4tQ453Vi3q5WexSUXaVgut69ro8MFnmHwuezAArEZTZyLr9fS6QotjqkSAxSF6d1aDgsPoX849izJ7m
    """

@pytest.fixture
def sample_i2p_addresses():
    return """
    # Basic I2P domains
    example.i2p
    blog.example.i2p
    sub.domain.example.i2p
    
    # With protocol
    http://example.i2p
    https://example.i2p
    
    # With ports
    example.i2p:8080
    http://example.i2p:8081
    
    # With paths
    http://example.i2p/path
    https://sub.example.i2p:8080/path/to/resource
    mail.domain.i2p/index.html
    """

@pytest.fixture
def sample_pgp_block():
    return """-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: OpenPGP.js v4.10.10
Comment: https://openpgpjs.org

xjMEXZNO6hYJKwYBBAHaRw8BAQdA88tb7cBPLHnHQUffjAX2zi/2YVzXbKFN
MelSwW9zVyzNJ2phdmllckBqdW5xdWVyYS5pbyA8amF2aWVyQGp1bnF1ZXJh
LmlvPsJ3BBAWCgAfBQJdk07qBgsJBwgDAgQVCAoCAxYCAQIZAQIbAwIeAQAK
CRCruS5mMrHGiKJ3AQC+BoJM3WxDF0egUKzQONkeniRcAaj+6H/wwCG/hRGs
0QD/dbAqhJ8zLsCXjpbUJ3kiwC0sxqoXNqkoSxEL3ussnALOOARdk07qEgor
BgEEAZdVAQUBAQdAx8UrusJR+LO5PacT+VQGBSBHl5BUIs3qWgIgZJ5u4DED
AQgHwmEEGBYIAAkFAl2TTuoCGwwACgkQq7kuZjKxxogVrAEAzTz3tEeHckeH
f66oXp3+7mkByue6sOAsPTO1q9cEzV8BALLe/3t7UOkCmisVlQ+ONuhko+yo
tZO/Nk0MH1tX+c0M
=Qj/6
-----END PGP PUBLIC KEY BLOCK-----"""

@pytest.fixture
def sample_communication_platforms():
    return """
    # WhatsApp URLs
    https://wa.me/34666777888
    https://wa.me/34666777888?text=Hello
    https://api.whatsapp.com/send?phone=34666777888
    https://chat.whatsapp.com/invite/abc123
    
    # Discord URLs
    https://discord.gg/abcd1234
    https://discord.com/invite/abcd1234
    https://discordapp.com/invite/abcd1234
    https://discord.me/server
    https://discord.io/server
    
    # Telegram URLs
    https://t.me/telegramchannel
    https://telegram.me/telegramchannel
    https://telegram.dog/telegramchannel
    https://t.me/joinchat/abcdef123456
    https://t.me/+abcdef123456
    https://t.me/c/123456789/1234
    
    # Skype URLs
    skype://join?id=abcd1234
    skype:echo123?call
    skype:echo123?chat
    skype:echo123?add
    https://join.skype.com/invite/abcd1234
    """

@pytest.fixture
def sample_hashes():
    return """
    MD5: d41d8cd98f00b204e9800998ecf8427e
    SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
    SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    """

@pytest.fixture
def sample_social_media():
    return """
    Twitter: @twitteruser
    @username
    https://twitter.com/username
    https://twitter.com/@username
    twitter.com/username
    ZeroNet: 1HeLLo4uzjaLetFx6NH3PMwFP3qbRbTf3D
    Paste: https://pastebin.com/abc123
    """

@pytest.fixture
def sample_contextual_data():
    return """
    Location: Michigan, United States
    Organization: Example Corp Ltd.
    Person: John Smith
    Keyphrase: "highly confidential internal document"
    BitName: example.bit
    """

#-----------------------------End of fixtures-----------------------------------

def test_item_base_class():
    item = Item("test value")
    assert str(item) == "Item(test value)"
    assert repr(item) == "Item(test value)"
    
    # Test truncation of long values
    item = Item("x" * 200)
    assert len(str(item)) < 150

def test_btc_wallet_validation():
    valid_btc = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    invalid_btc = "1invalid"
    
    assert BTC_Wallet.isvalid(valid_btc) == True
    assert BTC_Wallet.isvalid(invalid_btc) == False

def test_eth_wallet_validation():
    valid_eth = "0x0f52bdd5c7d3d7bca3bd78d7e1a5563e15530e24cd2f8db8a44c88dd93125514"
    invalid_eth = "0xinvalid"
    
    assert ETH_Wallet.isvalid(valid_eth) == True
    assert ETH_Wallet.isvalid(invalid_eth) == False

def test_pgp_key_handling(sample_pgp_data):
    pgp = PGP(sample_pgp_data)
    assert "PUBLIC KEY" in pgp.value
    assert pgp.is_public_key() == True
    assert pgp.is_private_key() == False

def test_restalker_initialization():
    # Test default initialization
    stalker = reStalker()
    for attr in dir(stalker):
        if "_" not in attr and attr not in ["parse"]:
            val = getattr(stalker, attr)
            assert val == False or val == []
    
    # Test all=True initialization
    stalker = reStalker(all=True)
    for attr in dir(stalker):
        if "_" not in attr and attr not in ["parse"]:
            val = getattr(stalker, attr)
            assert val == True or val == []

def test_email_detection(sample_communication_data):
    stalker = reStalker(email=True)
    results = list(stalker.parse(sample_communication_data))
    emails = [r for r in results if isinstance(r, Email)]
    assert len(emails) > 0
    assert "test@example.com" in str(emails[0])

def test_phone_detection(sample_communication_data):
    stalker = reStalker(phone=True)
    results = list(stalker.parse(sample_communication_data))
    phones = [r for r in results if isinstance(r, Phone)]
    assert len(phones) > 0
    assert "+1-555-123-4567" in str(phones[0])

def test_crypto_detection(sample_crypto_data):
    stalker = reStalker(btc_wallet=True, eth_wallet=True, xmr_wallet=True,
                        zec_wallet=True, dash_wallet=True, dot_wallet=True,
                        xrp_wallet=True, bnb_wallet=True)
    results = list(stalker.parse(sample_crypto_data))
    
    btc = [r for r in results if isinstance(r, BTC_Wallet)]
    eth = [r for r in results if isinstance(r, ETH_Wallet)]
    xmr = [r for r in results if isinstance(r, XMR_Wallet)]
    zec = [r for r in results if isinstance(r, ZEC_Wallet)]
    dash = [r for r in results if isinstance(r, DASH_Wallet)]
    dot = [r for r in results if isinstance(r, DOT_Wallet)]
    xrp = [r for r in results if isinstance(r, XRP_Wallet)]
    bnb = [r for r in results if isinstance(r, BNB_Wallet)]
    
    assert len(btc) > 0
    assert len(eth) > 0
    assert len(xmr) > 0
    assert len(zec) > 0
    assert len(dash) > 0    
    assert len(dot) > 0
    assert len(xrp) > 0
    assert len(bnb) > 0

def test_url_detection(sample_url_data):
    stalker = reStalker(tor=True, i2p=True, ipfs=True)
    results = list(stalker.parse(sample_url_data))
    
    tor = [r for r in results if isinstance(r, Tor_URL)]
    i2p = [r for r in results if isinstance(r, I2P_URL)]
    ipfs = [r for r in results if isinstance(r, IPFS_URL)]
    
    assert len(tor) > 0
    assert len(i2p) > 0
    assert len(ipfs) > 0

def test_analytics_code_detection():
    data = "Google Analytics: UA-12345678-9 and G-ABCDEFGHIJ"
    stalker = reStalker(gatc=True)
    results = list(stalker.parse(data))
    codes = [r for r in results if isinstance(r, GA_Tracking_Code)]
    assert len(codes) == 2
    assert "UA-12345678-9" in str(codes[0]) or "G-ABCDEFGHIJ" in str(codes[0])

def test_credentials_detection(sample_communication_data):
    stalker = reStalker(username=True, password=True)
    results = list(stalker.parse(sample_communication_data))
    
    usernames = [r for r in results if isinstance(r, Username)]
    passwords = [r for r in results if isinstance(r, Password)]
    
    assert len(usernames) > 0
    assert len(passwords) > 0
    assert "test_user_123" in str(usernames[0])
    assert "SecretPass123" in str(passwords[0])

def test_base64_detection():
    data = "SGVsbG8gV29ybGQ="  # "Hello World" in base64
    stalker = reStalker(base64=True)
    results = list(stalker.parse(data))
    b64 = [r for r in results if isinstance(r, Base64)]
    assert len(b64) > 0
    assert "SGVsbG8gV29ybGQ=" in str(b64[0])

def test_multiple_bitcoin_addresses(sample_bitcoin_addresses):
    stalker = reStalker(btc_wallet=True)
    results = list(stalker.parse(sample_bitcoin_addresses))
    
    btc_wallets = [r for r in results if isinstance(r, BTC_Wallet)]
    assert len(btc_wallets) == 4
    assert all(BTC_Wallet.isvalid(str(wallet).split('(')[1][:-1]) for wallet in btc_wallets)

def test_ethereum_address_case_sensitivity(sample_eth_addresses):
    stalker = reStalker(eth_wallet=True)
    results = list(stalker.parse(sample_eth_addresses))
    
    eth_wallets = [r for r in results if isinstance(r, ETH_Wallet)]
    # Verify that case-insensitive addresses are detected as the same
    unique_addresses = set(str(w) for w in eth_wallets)
    assert len(unique_addresses) == 2

def test_monero_address_validation(sample_monero_addresses):
    stalker = reStalker(xmr_wallet=True)
    results = list(stalker.parse(sample_monero_addresses))
    
    xmr_wallets = [r for r in results if isinstance(r, XMR_Wallet)]
    assert len(xmr_wallets) == 3
    # Verify standard length of Monero addresses
    assert all(len(str(wallet).split('(')[1][:-1]) >= 95 for wallet in xmr_wallets)

def test_i2p_url_detection(sample_i2p_addresses):
    stalker = reStalker(i2p=True)
    results = list(stalker.parse(sample_i2p_addresses))
    
    i2p_urls = [r for r in results if isinstance(r, I2P_URL)]
    assert len(i2p_urls) > 0
    assert any(".i2p" in str(url) for url in i2p_urls)

def test_pgp_key_analysis(sample_pgp_block):
    stalker = reStalker(pgp=True)
    results = list(stalker.parse(sample_pgp_block))
    
    pgp_keys = [r for r in results if isinstance(r, PGP)]
    assert len(pgp_keys) == 1
    assert pgp_keys[0].is_public_key()
    assert not pgp_keys[0].is_private_key()
    assert "OpenPGP.js" in str(pgp_keys[0])

def test_zeronet_detection(sample_social_media):
    stalker = reStalker(zeronet=True)
    results = list(stalker.parse(sample_social_media))
    
    zeronet = [r for r in results if isinstance(r, Zeronet_URL)]
    assert len(zeronet) > 0
    assert "1HeLLo4" in str(zeronet[0])

def test_zeronet_context_and_bitname(sample_contextual_data):
    stalker = reStalker(zeronet_ctxt=True, bitname=True)
    results = list(stalker.parse(sample_contextual_data))
    
    bitnames = [r for r in results if isinstance(r, Bitname_URL)]
    assert len(bitnames) > 0
    assert "example.bit" in str(bitnames[0]) #TODO: Remove empty valued objects

def test_paste_detection(sample_social_media):
    stalker = reStalker(paste=True)
    results = list(stalker.parse(sample_social_media))
    
    pastes = [r for r in results if isinstance(r, Paste)]
    assert len(pastes) > 0
    assert "pastebin.com" in str(pastes[0])

def test_twitter_detection(sample_social_media):
    stalker = reStalker(twitter=True)
    results = list(stalker.parse(sample_social_media))
    
    twitter = [r for r in results if isinstance(r, TW_Account)]
    print(twitter)
    assert len(twitter) > 0

def test_contextual_information(sample_contextual_data):
    stalker = reStalker(location=True, organization=True, keyphrase=True, own_name=True)
    results = list(stalker.parse(sample_contextual_data))
    
    locations = [r for r in results if isinstance(r, Location)]
    orgs = [r for r in results if isinstance(r, Organization)]
    keyphrases = [r for r in results if isinstance(r, Keyphrase)]
    names = [r for r in results if isinstance(r, OwnName)]
    
    assert len(locations) > 0 and "Michigan" in str([x.value for x in locations])
    assert len(orgs) > 0 and "Example Corp" in str([x.value for x in orgs])
    assert len(keyphrases) > 0 and "confidential" in str([x.value for x in keyphrases])
    assert len(names) > 0 and "John Smith" in str([x.value for x in names])

def test_messaging_platforms(sample_communication_platforms):
    stalker = reStalker(whatsapp=True, discord=True, telegram=True, skype=True)
    results = list(stalker.parse(sample_communication_platforms))
    
    whatsapp = [r for r in results if isinstance(r, Whatsapp_URL)]
    discord = [r for r in results if isinstance(r, Discord_URL)]
    telegram = [r for r in results if isinstance(r, Telegram_URL)]
    skype = [r for r in results if isinstance(r, Skype_URL)]
    
    assert len(whatsapp) == 4
    assert len(discord) == 5
    assert len(telegram) == 6
    assert len(skype) == 5

def test_hash_detection(sample_hashes):
    stalker = reStalker(md5=True, sha1=True, sha256=True)
    results = list(stalker.parse(sample_hashes))
    
    md5_hashes = [r for r in results if isinstance(r, MD5)]
    sha1_hashes = [r for r in results if isinstance(r, SHA1)]
    sha256_hashes = [r for r in results if isinstance(r, SHA256)]
    
    assert len(md5_hashes) > 0 and len(str(md5_hashes[0])) == 32 + 5 #len + wrapper
    assert len(sha1_hashes) > 0 and len(str(sha1_hashes[0])) == 40 + 6 #len + wrapper
    assert len(sha256_hashes) > 0 and len(str(sha256_hashes[0])) == 64 + 8 #len + wrapper