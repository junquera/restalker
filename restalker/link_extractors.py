from urllib.parse import urlparse
from hashlib import md5
from . import restalker
import re

def looks_like_link(l):
    if re.match(restalker.any_url, l):
        return True
    else:
        proto = l.split('://')
        if len(proto) > 1:
            return len(proto[1].split('.')) > 1
        else:
            url = proto[0].split('.')
            if len(url) > 1:
                return len(("".join(url[1:])).split('/')) > 1
            else:
                return False


# TODO Heredar de urlparse
# Unique URL Former
class UUF():

    # TODO ¿Cómo tratar el '#' en la URL?

    service_port = {
        'http': 80,
        'https': 443,
        'ssh': 22,
        'sftp': 22,
        'ftp': 21,
        'irc': 194
    }

    built = 0

    def __init__(self, url):
        while self.built <= 1:
            parse = urlparse(url)
            self.scheme = parse.scheme
            self.netloc = parse.netloc
            self.path = parse.path
            self.params = parse.params,
            self.query = parse.query
            self.fragment = parse.fragment

            self.protocol = self.scheme

            domain_port = self.netloc.split(':')

            self.domain = domain_port[0]

            if self.netloc == '':
                if self.path == '':
                    self.signature = None
                else:
                    self.netloc = self.path.split('/')[0]
                    self.path = "/" + "/".join(self.path.split('/')[1:])

            # TODO Hay que replantearse cómo hacer el análisis de dominio/protocolo
            if len(domain_port) > 1:
                self.port = self.service_port.get(domain_port[1], self.service_port.get(self.scheme))
            else:
                self.port = 80

            if len(self.protocol) == 0:
                self.protocol = 'http'
                for service in self.service_port:
                    if self.service_port[service] == self.port:
                        self.protocol = service
                        break
                self.scheme = self.protocol


            if len(self.query) > 0:
                query_args = {a[0]: (a[1] if len(a) > 1 else None) for a in (arg.split('=') for arg in self.query.split('&'))}

                args = []
                # Sort the query args to be allways the same
                for arg in sorted(query_args.keys()):
                    if query_args[arg]:
                        args.append('%s=%s' % (arg, query_args[arg]))
                    else:
                        args.append('%s' % arg)

                self.full_path = '%s?%s' % (self.path, '&'.join(args))
            else:
                self.full_path = self.path

            url = self.end_build()

        self.rebuild()


    def end_build(self):
        self.built += 1
        return '%s://%s%s' % (self.protocol, self.netloc, self.full_path)

    def rebuild(self):
        self.full_url = '%s://%s%s' % (self.protocol, self.netloc, self.full_path)
        self.signature = md5(self.full_url.encode('utf8')).hexdigest()

        return self.full_url
