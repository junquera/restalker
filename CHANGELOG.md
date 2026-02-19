# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.1] - 2026-02-13

### Added

- **`use_ner` parameter** - New optional boolean parameter in `reStalker.__init__()` (default: `False`)
  - Set `use_ner=True` to enable GLiNER2-based extraction (person names, organizations, locations)
  - Set `use_ner=False` (default) to use only regex-based extraction (faster, no model loading)
  - Existing code without `use_ner` continues to work unchanged

### Fixed

- **BTC/Bitname Detection** (PR #50 by [@robeertosv](https://github.com/robeertosv)): Bitcoin Legacy addresses no longer incorrectly detected as Bitname URLs. Added `.bit` domain validation for Bitname URLs and explicit `bitname://` scheme support.
- **Trailing Punctuation** (PR #51 by [@robeertosv](https://github.com/robeertosv)): Email addresses and all cryptocurrency wallet addresses (BTC, ETH, XMR, ZEC, DASH, DOT, XRP, BNB) now strip trailing `.`, `,`, `;` characters from matched values.

### Removed

- **Metadata Extraction**: Removed `restalker/metadata.py` module. The feature was not part of the core IOC extraction functionality.
  - Related dependencies removed: `pyexifinfo`, `PyPDF2`, `olefile`
  - **Alternative**: Use dedicated libraries directly (`exiftool`, `PyPDF2`, `python-docx`) if you need metadata extraction.

---

## [2.2.0] - 2026-02-12

### 🎉 Major Update: GLiNER2 Integration

This release upgrades reStalker from GLiNER v0.2.25 to **GLiNER2 v1.2.4**, bringing significant improvements in accuracy, performance, and reduced dependencies.

### Added

- **GLiNER2 v1.2.4** - Upgraded from GLiNER v0.2.25 for better entity extraction
- **Enhanced Phone Detection** - New hex filtering system prevents false positives from cryptographic hashes, wallet addresses, and hex strings
- **Context Validation** - New `is_valid_context()` helper ensures entities are extracted only in valid contexts, preventing substring matches
- **Multi-line Entity Splitting** - New `split_entities()` helper correctly handles entities spanning multiple lines
- **Comprehensive Test Suite** - Added 12 new tests for phone vs hash detection in `tests/test_hash_phone_detection.py`

### Changed

- **Model Upgrade**: Switched from `nvidia/gliner-PII` to `fastino/gliner2-large-v1` (340M parameters)
- **API Update**: GLiNER's `predict_entities()` replaced with `extract_entities()` (internal change, no user-facing impact)
- **Dependency Simplification**: Removed TensorFlow dependency (no longer required by GLiNER2)
- **Improved `_analyze_chunk()` method**: Complete rewrite (478 → 650 lines) with enhanced phone detection logic and context validation for all regex-based extractions

### Fixed

- **False Positive Prevention**: Phone-like patterns in MD5, SHA1, SHA256 hashes no longer detected as phone numbers
- **Crypto Wallet Protection**: Bitcoin, Ethereum, and other wallet addresses containing phone-like sequences are correctly identified as wallets, not phones
- **Hex String Filtering**: Phone-like patterns at hash boundaries (e.g., `a1b2c3567890def`) are no longer extracted as phones
- **Substring Match Prevention**: Context validation ensures entities are not extracted from the middle of other entities (e.g., "example" not extracted as a name from "myemail@example.com")

### Migration Guide

#### For Most Users (No Changes Required)

If you're using reStalker's public API, **no code changes are needed**:

```python
# This code works exactly the same in v2.2.0
import restalker

stalker = restalker.reStalker(phone=True, email=True, btc_wallet=True)
results = stalker.parse(input_text)
```

#### What's Different Under the Hood

1. **Dependency**: `gliner` → `gliner2` (automatically handled by pip/poetry)
2. **Model**: Downloads `fastino/gliner2-large-v1` (~340MB) on first use
3. **Accuracy**: Fewer false positives, especially for phone numbers near hashes/crypto addresses
4. **Performance**: Slightly faster inference with GLiNER2's optimizations

#### Known Issues

- None at time of release.

### Credits

This release incorporates significant improvements from **PR #47** by [@contributor](https://github.com/junquera/restalker/pull/47). Special thanks for the enhanced phone detection logic and comprehensive testing suite.

### Technical Details

**Dependencies Updated:**
- `gliner>=0.2.25` → `gliner2>=1.2.4`

**Files Changed:**
- `pyproject.toml` - Version bump to 2.2.0, dependency update
- `requirements.txt` - GLiNER2 dependency
- `setup.py` - GLiNER2 dependency
- `poetry.lock` - Regenerated with GLiNER2 1.2.4
- `restalker/__init__.py` - Version string updated to "2.2.0"
- `restalker/restalker.py` - Complete `_analyze_chunk()` rewrite, new helpers, GLiNER2 API migration
- `restalker/textan.py` - GLiNER2 migration, model update, TensorFlow suppression removed
- `tests/test_hash_phone_detection.py` - New comprehensive test suite (12 tests)

**Test Coverage:**
- Total tests: 46
- Passing: 46 (100%)
- Coverage: 70.53%

---

## [2.1.1] - 2024-XX-XX

### Fixed
- Type safety improvements in wallet validation methods
- Circular import fix in `__init__.py`

---

## [2.1.0] - 2024-XX-XX

### Added
- Initial GLiNER integration for Named Entity Recognition
- Support for GPU acceleration (CUDA and ROCm)
- Comprehensive cryptocurrency wallet detection
- Enhanced dark web and alternative network URL detection

---

[2.2.1]: https://github.com/junquera/restalker/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/junquera/restalker/compare/v2.1.1...v2.2.0
[2.1.1]: https://github.com/junquera/restalker/compare/v2.1.0...v2.1.1
[2.1.0]: https://github.com/junquera/restalker/releases/tag/v2.1.0
