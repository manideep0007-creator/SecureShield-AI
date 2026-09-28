import httpx
import filetype
import os
from app.preprocessing.safe_url_fetcher import SafeURLFetcher

async def resolve_url(url: str) -> str:
    """Resolve shortened or redirected links to their final URL securely."""
    try:
        return await SafeURLFetcher.resolve_redirects(url)
    except Exception:
        return url  # fallback to original URL on failure

def check_file_type(file_bytes: bytes, declared_filename: str) -> dict:
    """Check file type by magic bytes vs declared extension."""
    kind = filetype.guess(file_bytes)
    declared_ext = os.path.splitext(declared_filename)[1].lower().strip(".")
    
    actual_ext = kind.extension if kind else "unknown"
    actual_mime = kind.mime if kind else "application/octet-stream"
    
    extension_mismatch = False
    if kind and declared_ext and declared_ext != actual_ext:
        # allow some aliases e.g., jpeg == jpg
        aliases = {"jpg": "jpeg", "jpeg": "jpg", "htm": "html", "html": "htm"}
        if aliases.get(declared_ext) != actual_ext:
            extension_mismatch = True
            
    return {
        "actual_mime": actual_mime,
        "actual_ext": actual_ext,
        "declared_ext": declared_ext,
        "extension_mismatch": extension_mismatch
    }
