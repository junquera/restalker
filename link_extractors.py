from urllib.parse import urlparse
from hashlib import md5


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

    def __init__(self, url):
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

        if len(domain_port) > 1:
            self.port = self.service_port.get(domain_port[1], 80)
        else:
            self.port = 80

        if self.netloc == '':
            if self.path == '':
                self.signature = None
            else:
                self.netloc = self.path.split('/')[0]
                self.path = '/'

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

        self.full_url = self.rebuild()

    def rebuild(self):

            self.full_url = '%s://%s%s' % (self.protocol, self.netloc, self.full_path)
            self.signature = md5(self.full_url.encode('utf8')).hexdigest()

            return self.full_url
