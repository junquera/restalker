from .restalker import *
from . import link_extractors
from .spacy_singleton import get_spacy_model, is_spacy_available

# Initialize spaCy model singleton on import
get_spacy_model()

__version__ = "1.2.1"
