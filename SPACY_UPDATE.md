# GLiNER Migration

This project has been migrated to use [nvidia GLiNER](https://huggingface.co/nvidia/gliner-PII) instead of spaCy for named entity recognition. This update provides several advantages:

## Benefits of migrating to GLiNER

1. **Zero-shot NER**: GLiNER can recognize entities without requiring specific training data for each entity type.
2. **Automatic model download**: Models are automatically downloaded from HuggingFace on first use.
3. **No language-specific models**: Works across multiple languages without downloading separate models.
4. **Modern architecture**: Built on transformer-based models for better accuracy.
5. **Simpler setup**: No need to manually download or configure language-specific models.
6. **Privacy-focused**: The nvidia/gliner-PII model is specifically designed for PII detection.

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

That's it! The GLiNER model will be automatically downloaded from HuggingFace on first use.

### 2. First run

On the first run, GLiNER will automatically download the `nvidia/gliner-PII` model from HuggingFace. This requires internet connectivity but only needs to be done once. The model is cached locally for subsequent uses.

## Testing

To test entity extraction functionality:

```bash
python test.py [text_file_path]
```

To specifically test text analysis functionality:

```bash
python test_textan.py
```

To test GLiNER directly:

```bash
python testing/test_gliner.py
```

## API Changes

The external API remains backward compatible. The following classes and methods continue to work the same way:

- `reStalker` - The main class for entity extraction
- `TextAnalysis` - Text analysis for keyword and phrase extraction

## Note for Developers

If you're developing with this library, keep in mind that we now internally use GLiNER models. The entity recognition is now powered by transformer-based models which provide better accuracy and don't require language-specific model downloads.