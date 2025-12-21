# Function to initialize spaCy model for tests
def initialize_spacy_model():
    """
    Initialize and load an appropriate spaCy model for testing.
    Returns the loaded model or None if no model could be loaded.
    """
    try:
        import spacy
        try:
            return spacy.load("es_core_news_md")
        except OSError:
            try:
                return spacy.load("en_core_web_md")
            except OSError:
                try:
                    return spacy.load("en_core_web_sm")
                except OSError:
                    print("Warning: No spaCy model found. NER tests may fail.")
                    print("Please run: python -m spacy download en_core_web_sm")
                    return None
    except ImportError:
        print("Warning: spaCy not installed. NER tests may fail.")
        return None