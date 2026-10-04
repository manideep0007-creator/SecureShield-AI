# V2 Preprocessing Layer
# Enhanced input sanitization, URL resolution, file validation, and data normalization.
# V1 preprocessing remains at backend/preprocessing/data_prep.py (unchanged).

from app.preprocessing.data_prep import resolve_url, check_file_type
from app.preprocessing.safe_url_fetcher import SafeURLFetcher
from app.preprocessing.v2_preprocessor import (
    V2Preprocessor,
    PreprocessingResult,
    PreprocessingStatus,
    normalize_text,
    normalize_url,
    normalize_file,
    normalize_email_metadata,
    MAX_FILE_BYTES,
    MAX_TEXT_LENGTH,
    MAX_URL_LENGTH,
    MAX_FILENAME_LENGTH,
    MAX_METADATA_ITEMS,
    MAX_LIST_ITEMS,
    MAX_RECEIVED_HOPS,
)

__all__ = [
    "resolve_url",
    "check_file_type",
    "SafeURLFetcher",
    "V2Preprocessor",
    "PreprocessingResult",
    "PreprocessingStatus",
    "normalize_text",
    "normalize_url",
    "normalize_file",
    "normalize_email_metadata",
    "MAX_FILE_BYTES",
    "MAX_TEXT_LENGTH",
    "MAX_URL_LENGTH",
    "MAX_FILENAME_LENGTH",
    "MAX_METADATA_ITEMS",
    "MAX_LIST_ITEMS",
    "MAX_RECEIVED_HOPS",
]
