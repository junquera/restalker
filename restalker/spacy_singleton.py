"""
Shared spaCy model singleton to avoid redundant loading.
"""
import spacy


class SpacyModelSingleton:
    """Singleton class to manage spaCy model loading."""
    
    _instance = None
    _model = None
    _model_loaded = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SpacyModelSingleton, cls).__new__(cls)
        return cls._instance
    
    def get_model(self):
        """Get the spaCy model, loading it if necessary."""
        if not self._model_loaded:
            try:
                self._model = spacy.load("en_core_web_sm")
                print("spaCy model 'en_core_web_sm' loaded successfully.")
            except OSError:
                print("Warning: spaCy model 'en_core_web_sm' not found. NER functionality will be limited.")
                self._model = None
            self._model_loaded = True
        
        return self._model
    
    def is_available(self):
        """Check if the spaCy model is available."""
        if not self._model_loaded:
            self.get_model()  # Attempt to load if not already tried
        return self._model is not None


# Create a global instance for easy access
spacy_model = SpacyModelSingleton()


def get_spacy_model():
    """Convenience function to get the spaCy model."""
    return spacy_model.get_model()


def is_spacy_available():
    """Convenience function to check if spaCy model is available."""
    return spacy_model.is_available()
