# Function to initialize GLiNER2 model for tests
def initialize_gliner_model():
    """
    Initialize and load the GLiNER2 model for testing.
    Returns the loaded model or None if the model could not be loaded.
    """
    try:
        # Disable tensorflow warnings if present
        import sys
        sys.modules['tensorflow'] = None
        
        from gliner2 import GLiNER2
        try:
            # Load GLiNER2 model for PII and entity detection
            return GLiNER2.from_pretrained('fastino/gliner2-large-v1')
        except Exception as e:
            print(f"Warning: Could not load GLiNER2 model. NER tests may fail. Error: {e}")
            print("Please ensure you have internet connectivity for the first download.")
            return None
    except ImportError:
        print("Warning: GLiNER2 not installed. NER tests may fail.")
        print("Please run: pip install gliner2")
        return None