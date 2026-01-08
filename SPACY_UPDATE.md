# spaCy Update

This project branch has been updated to use [spaCy](https://spacy.io/) instead of NLTK for natural language processing. This update provides several advantages:

## Benefits of migrating to spaCy

1. **Improved performance**: spaCy is optimized for production and offers better performance.
2. **Integrated pipeline**: Complete NLP pipeline in a single object, rather than isolated functions.
3. **Enhanced entity recognition**: More accurate and modern NER (Named Entity Recognition) models.
4. **Multilingual support**: Pre-trained models available in multiple languages.
5. **Active maintenance**: Frequent updates and extensive community support.

## Setup for using spaCy

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure spaCy models

Run the setup script to automatically install the necessary models:

```bash
python setup_spacy.py
```

Alternatively, you can install the models manually:

```bash
# For Spanish (recommended)
python -m spacy download es_core_news_md

# Or for English
python -m spacy download en_core_web_md

# Or the small version (faster but less accurate)
python -m spacy download en_core_web_sm
```

## Testing

To test entity extraction functionality:

```bash
python test.py [text_file_path]
```

To specifically test text analysis functionality:

```bash
python test_textan.py
```

## API Changes

The external API remains backward compatible. The following classes and methods continue to work the same way:

- `reStalker` - The main class for entity extraction
- `TextAnalysis` - Text analysis for keyword and phrase extraction

## Note for Developers

If you're developing with this library, keep in mind that we now internally use spaCy models. Performance and results may vary slightly compared to the NLTK-based version.