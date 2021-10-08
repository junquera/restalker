import pyexifinfo as p
import uuid
import io
import os
import magic
from PyPDF2 import PdfFileReader
import olefile
from hashlib import sha256

def contains_metadata(byte_array):
    with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
        t = m.id_buffer(byte_array)

    return t.find('image') == 0 or t.find('application/pdf') == 0

def is_bin(b):

    if type(b) != bytes:
        return False
    else:
        try:
            # If its "decodeable", its not a file
            b.decode('utf8')
            return False
        except Exception as e:
            pass

    return True

class Metadata():

    def __init__(self, signature=None, tags={}):
        self.signature = signature
        self.tags = tags

    def __str__(self):
        return ("%s: %s" % (self.signature, self.tags))

def get_metadata(byte_array):

    if not is_bin(byte_array):
        return {}

    with magic.Magic(flags=magic.MAGIC_MIME_TYPE) as m:
        t = m.id_buffer(byte_array)

    try:
        if t.find('image') == 0:
            tags = get_image_metadata(byte_array)
        elif t.find('application/pdf') == 0:
            tags = get_pdf_metadata(byte_array)
    except Exception as e:
        tags = {}
    signature = sha256(byte_array).hexdigest()

    m = Metadata(signature=signature, tags=tags)

    return m

def get_video_metadata(byte_array):
    pass

def get_ofimatica_metadata(byte_array):

    try:
        ole = olefile.OleFileIO(sys.argv[1])
    except IndexError as ie:
        tags = {}

    # parse and display metadata:
    meta = ole.get_metadata()

    print(meta)


class TmpFile():

    def __init__(self, byte_array):
        filename = '/tmp/%s' % uuid.uuid4()
        self._filename = filename
        self._size = len(byte_array)
        with open(filename, 'wb+') as f:
            f.write(byte_array)

    def get_name(self):
        return self._filename

    def safe_delete(self):
        block_size = 1024
        to_delete = self._size
        while to_delete % block_size > 0:
            to_delete+=1

        with open(self._filename, 'wb+') as f:
            while to_delete > 0:
                f.write(bytearray(block_size * b'\x00'))
                to_delete -= block_size
            f.flush()

        self.delete()

    def delete(self):
        try:
            os.remove(self._filename)
        except Exception as e:
            print("Error deleting %s" % self._filename)


def get_image_metadata(byte_array):

    try:
        exif_json = p.get_json(filename)
        tags = exif_json[0]
    except Exception as e:
        tags = {}

    return tags


def get_pdf_metadata(byte_array):

    v = io.BytesIO(byte_array)

    try:
        pdf = PdfFileReader(v)
        tags = pdf.getDocumentInfo()
    except Exception as e:
        tags = {}
    return tags


def format_metadata(tags):
    res = ''
    for tag in tags.keys():
        res += '%s\t%s\n' % (tag, tags[tag])
    return res


t = TmpFile('abcde'.encode('utf-8'))
t.safe_delete()
#
#
# with open('/home/junquera/Imágenes/stranger-kids-portada.jpg', 'rb') as f:
#     print(get_metadata(f.read()))
