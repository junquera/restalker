from .restalker import reStalker as reStalker
from . import link_extractors as link_extractors

import nltk
nltk.download('stopwords')
nltk.download('punkt')


__version__ = "1.2.1"
