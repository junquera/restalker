import re

gpg_header = '-----BEGIN PGP PUBLIC KEY BLOCK-----'
gpg_footer = '-----END PGP PUBLIC KEY BLOCK-----'

gpg_key = "(%s\n(?:.{,64}\n){,128}%s)\n" % (gpg_header, gpg_footer)

with open('alan@foundries.io.asc') as f:
    k = f.read()

print(re.match(gpg_key, k))
