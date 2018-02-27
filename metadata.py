import pyexifinfo as p
import uuid
import io
import os
import magic
from PyPDF2 import PdfFileReader


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
        except:
            pass

    return True


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
    except:
        tags = {}
    return tags


def get_image_metadata(byte_array):

    filename = '/tmp/%s' % uuid.uuid4()
    with open(filename, 'wb+') as f:
        f.write(byte_array)

    try:
        exif_json = p.get_json(filename)
        tags = exif_json[0]
    except:
        tags = {}

    try:
        os.remove(filename)
    except:
        print("Error deleting %s" % filename)


    return tags


def get_pdf_metadata(byte_array):

    v = io.BytesIO(byte_array)

    try:
        pdf = PdfFileReader(v)
        tags = pdf.getDocumentInfo()
    except:
        tags = {}
    return tags


def format_metadata(tags):
    res = ''
    for tag in tags.keys():
        res += '%s\t%s\n' % (tag, tags[tag])
    return res


with open('/home/junquera/Imágenes/stranger-kids-portada.jpg', 'rb') as f:
    print(get_metadata(f.read()))
