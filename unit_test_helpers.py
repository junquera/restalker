# Function to initialize GLiNER model for tests
def initialize_gliner_model():
    """
    Initialize and load the GLiNER model for testing.
    Returns the loaded model or None if the model could not be loaded.
    """
    try:
        # Disable tensorflow warnings if present
        import sys
        sys.modules['tensorflow'] = None
        
        from gliner import GLiNER
        try:
            # Load nvidia's GLiNER model for PII detection
            return GLiNER.from_pretrained('nvidia/gliner-PII')
        except Exception as e:
            print(f"Warning: Could not load GLiNER model. NER tests may fail. Error: {e}")
            print("Please ensure you have internet connectivity for the first download.")
            return None
    except ImportError:
        print("Warning: GLiNER not installed. NER tests may fail.")
        print("Please run: pip install gliner")
        return None