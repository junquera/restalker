import sys
import re

gpg_header = '-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----'
gpg_footer = '-----END PGP (PUBLIC|PRIVATE) KEY BLOCK-----'

gpg_key = "(%s\n(?:.{,64}\n){,128}%s)\n" % (gpg_header, gpg_footer)

with open(sys.argv[1]) as f:
    k = f.read()

print(re.match(gpg_key, k)[1])
