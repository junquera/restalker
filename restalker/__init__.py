from .restalker import *
from . import link_extractors

# Initialize spaCy model if available
try:
    import spacy
    spacy.load("en_core_web_sm")
except (ImportError, OSError):
    print("Warning: spaCy model 'en_core_web_sm' not available. Some NER functionality may be limited.")

__version__ = "1.2.1"
