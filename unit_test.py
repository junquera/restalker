import pytest

"""  README

For testing with spaCy NER functionality, make sure to install spaCy and download the English model:

python -m spacy download en_core_web_sm
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
    
    # Verify that locations were found and that Michigan is among them
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

# Test spaCy-based IOC detection - requires 'python -m spacy download en_core_web_sm'

@pytest.fixture
def sample_spacy_person_data():
    """Test data specifically designed for person name detection using spaCy NER"""
    return """
    The investigation team included John Smith, Maria Garcia, and Robert Johnson.
    Contact person: Dr. Sarah Williams (PhD in Computer Science).
    Witness testimony by Michael Brown and Jennifer Davis.
    Report submitted by: Alex Thompson, Senior Analyst.
    Person: Jane Anderson provided additional information.
    Mr. David Wilson and Ms. Lisa Taylor were present during the meeting.
    """

@pytest.fixture
def sample_spacy_location_data():
    """Test data for location detection using spaCy NER"""
    return """
    The incident occurred in New York City, United States.
    Suspects were last seen in London, England and Paris, France.
    Location: Los Angeles, California
    Evidence was found in Tokyo, Japan and Berlin, Germany.
    Investigation expanded to Sydney, Australia.
    Reports came from Toronto, Canada and Mexico City, Mexico.
    Additional leads in Rome, Italy and Moscow, Russia.
    Barcelona, Madrid, Chicago, Boston
    """

@pytest.fixture
def sample_spacy_organization_data():
    """Test data for organization detection using spaCy NER"""
    return """
    The breach affected Microsoft Corporation and Apple Inc.
    Investigation by Federal Bureau of Investigation (FBI).
    Organization: Google LLC was notified about the incident.
    Collaboration with Amazon Web Services and IBM Systems.
    Reports submitted to Securities Exchange Commission.
    Acme Corporation Ltd. and Example Technologies Inc. were involved.
    Partnership with BytonLabs Solutions and CyberSec Group.
    NATO and United Nations issued statements.
    Organization: Tesla Motors reported similar incidents.
    """

@pytest.fixture
def sample_mixed_spacy_data():
    """Mixed data containing persons, locations, and organizations"""
    return """
    John Doe from Microsoft visited our New York office.
    Sarah Johnson at Google's Mountain View, California headquarters.
    The FBI agent, Robert Smith, investigated the incident in Washington, DC.
    Dr. Maria Garcia from MIT presented research in Boston, Massachusetts.
    Apple Inc. CEO Tim Cook announced new products in Cupertino.
    Location: Seattle, Washington
    Organization: Amazon Corporation
    Person: Jeff Bezos
    """

def test_spacy_person_detection(sample_spacy_person_data):
    """Test detection of person names using spaCy NER"""
    stalker = reStalker(own_name=True)
    results = list(stalker.parse(sample_spacy_person_data))
    
    names = [r for r in results if isinstance(r, OwnName)]
    assert len(names) > 0, "Should detect person names using spaCy"
    
    # Check for specific names
    name_values = [n.value for n in names]
    expected_names = ["John Smith", "Maria Garcia", "Robert Johnson", 
                     "Sarah Williams", "Michael Brown", "Jennifer Davis",
                     "Alex Thompson", "Jane Anderson", "David Wilson", "Lisa Taylor"]
    
    found_names = []
    for expected in expected_names:
        if any(expected in name for name in name_values):
            found_names.append(expected)
    
    assert len(found_names) >= 3, f"Should find at least 3 person names, found: {found_names}"

def test_spacy_location_detection(sample_spacy_location_data):
    """Test detection of locations using spaCy NER"""
    stalker = reStalker(location=True)
    results = list(stalker.parse(sample_spacy_location_data))
    
    locations = [r for r in results if isinstance(r, Location)]
    assert len(locations) > 0, "Should detect locations using spaCy"
    
    # Check for specific locations
    location_values = [l.value for l in locations]
    expected_locations = ["New York City", "United States", "London", "England", 
                         "Paris", "France", "Los Angeles", "California", 
                         "Tokyo", "Japan", "Berlin", "Germany"]
    
    found_locations = []
    for expected in expected_locations:
        if any(expected in loc for loc in location_values):
            found_locations.append(expected)
    
    assert len(found_locations) >= 4, f"Should find at least 4 locations, found: {found_locations}"

def test_spacy_organization_detection(sample_spacy_organization_data):
    """Test detection of organizations using spaCy NER"""
    stalker = reStalker(organization=True)
    results = list(stalker.parse(sample_spacy_organization_data))
    
    organizations = [r for r in results if isinstance(r, Organization)]
    assert len(organizations) > 0, "Should detect organizations using spaCy"
    
    # Check for specific organizations
    org_values = [o.value for o in organizations]
    expected_orgs = ["Microsoft Corporation", "Apple Inc.", "Google LLC", 
                    "Federal Bureau of Investigation", "Amazon Web Services",
                    "IBM Systems", "Securities Exchange Commission"]
    
    found_orgs = []
    for expected in expected_orgs:
        if any(expected in org or org in expected for org in org_values):
            found_orgs.append(expected)
    
    assert len(found_orgs) >= 3, f"Should find at least 3 organizations, found: {found_orgs}"

def test_spacy_mixed_entity_detection(sample_mixed_spacy_data):
    """Test detection of mixed entities (persons, locations, organizations) in same text"""
    stalker = reStalker(own_name=True, location=True, organization=True)
    results = list(stalker.parse(sample_mixed_spacy_data))
    
    names = [r for r in results if isinstance(r, OwnName)]
    locations = [r for r in results if isinstance(r, Location)]
    organizations = [r for r in results if isinstance(r, Organization)]
    
    assert len(names) > 0, "Should detect person names"
    assert len(locations) > 0, "Should detect locations" 
    assert len(organizations) > 0, "Should detect organizations"
    
    # Verify specific entities
    name_values = [n.value for n in names]
    location_values = [l.value for l in locations]
    org_values = [o.value for o in organizations]
    
    # Check for expected entities
    assert any("John Doe" in name for name in name_values), "Should find John Doe"
    assert any("New York" in loc for loc in location_values), "Should find New York"
    assert any("Microsoft" in org for org in org_values), "Should find Microsoft"

def test_spacy_without_nlp_model():
    """Test behavior when spaCy model is not available"""
    stalker = reStalker(own_name=True, location=True, organization=True)
    
    # Simulate missing spaCy model by setting nlp to None
    original_nlp = stalker.nlp
    stalker.nlp = None
    
    test_data = "John Smith works at Microsoft in New York."
    results = list(stalker.parse(test_data))
    
    # Should not crash and should return empty results for NER-based entities
    names = [r for r in results if isinstance(r, OwnName)]
    locations = [r for r in results if isinstance(r, Location)]
    organizations = [r for r in results if isinstance(r, Organization)]
    
    # Without spaCy model, these should be empty or very limited
    assert len(names) == 0 or len(names) < 2, "Should have limited or no results without spaCy model"
    
    # Restore original nlp for other tests
    stalker.nlp = original_nlp

def test_spacy_entity_filtering():
    """Test that spaCy entities are properly filtered and cleaned"""
    stalker = reStalker(own_name=True, location=True, organization=True)
    
    # Test data with potential false positives and edge cases
    test_data = """
    Person: This should not be detected as a person name.
    Location: This should not be detected as a location.
    Organization: This should not be detected as an organization.
    
    Real person: Albert Einstein
    Real location: Switzerland  
    Real organization: NASA and Microsoft Corporation
    """
    
    results = list(stalker.parse(test_data))
    
    names = [r for r in results if isinstance(r, OwnName)]
    locations = [r for r in results if isinstance(r, Location)]  
    organizations = [r for r in results if isinstance(r, Organization)]
    
    # Check that labels are filtered out
    name_values = [n.value for n in names]
    location_values = [l.value for l in locations]
    org_values = [o.value for o in organizations]
    
    # Should not contain the label text itself
    assert not any("Person:" in name for name in name_values), "Should filter out 'Person:' labels"
    assert not any("Location:" in loc for loc in location_values), "Should filter out 'Location:' labels"  
    assert not any("Organization:" in org for org in org_values), "Should filter out 'Organization:' labels"
    
    # Should contain real entities
    assert any("Einstein" in name for name in name_values), "Should detect real person names"
    assert any("Switzerland" in loc for loc in location_values), "Should detect real locations"
    assert any(("NASA" in org or "Microsoft" in org) for org in org_values), "Should detect real organizations"

def test_spacy_performance_with_large_text():
    """Test spaCy performance with larger text blocks"""
    stalker = reStalker(own_name=True, location=True, organization=True)
    
    # Create a larger text block with repeated entities
    large_text = """
    Investigation Report Summary:
    
    This comprehensive investigation was conducted by Special Agent John Smith from the Federal Bureau of Investigation,
    in collaboration with Agent Sarah Johnson from the Central Intelligence Agency. The investigation spanned multiple
    locations including New York City, Los Angeles, Chicago, and Washington DC.
    
    Key organizations involved included Microsoft Corporation, Google LLC, Apple Inc., and Amazon Web Services.
    Additional cooperation was provided by the National Security Agency and Department of Homeland Security.
    
    Primary contacts were Dr. Michael Brown from MIT, Professor Lisa Davis from Stanford University, and 
    Director Robert Wilson from the Cybersecurity and Infrastructure Security Agency.
    
    The investigation covered incidents in London, Paris, Tokyo, Berlin, and Sydney, involving international
    cooperation with Interpol, European Union Agency for Cybersecurity, and various national law enforcement agencies.
    """ * 3  # Repeat to make it larger
    
    results = list(stalker.parse(large_text))
    
    names = [r for r in results if isinstance(r, OwnName)]
    locations = [r for r in results if isinstance(r, Location)]
    organizations = [r for r in results if isinstance(r, Organization)]
    
    # Should handle large text without issues
    assert len(names) > 5, f"Should detect multiple person names in large text, found: {len(names)}"
    assert len(locations) > 8, f"Should detect multiple locations in large text, found: {len(locations)}"
    assert len(organizations) > 5, f"Should detect multiple organizations in large text, found: {len(organizations)}"