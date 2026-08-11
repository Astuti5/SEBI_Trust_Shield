"""
detection/ocr_service.py

Extracts text from an uploaded screenshot so the scam-language and
impersonation detectors have something to work on.

Requires the `tesseract-ocr` system binary (apt install tesseract-ocr)
plus the `pytesseract` + `Pillow` Python packages. Fails loudly with a
clear message if the binary isn't installed, rather than silently
returning empty text — a silent OCR failure would make every downstream
score look artificially "safe."
"""

from __future__ import annotations

import io

try:
    import pytesseract
    from PIL import Image
    _OCR_AVAILABLE = True
except ImportError:
    _OCR_AVAILABLE = False


class OCRUnavailableError(RuntimeError):
    pass


def extract_text(image_bytes: bytes) -> str:
    if not _OCR_AVAILABLE:
        raise OCRUnavailableError(
            "OCR dependencies missing. Install with: "
            "apt-get install -y tesseract-ocr && pip install pytesseract Pillow"
        )
    try:
        image = Image.open(io.BytesIO(image_bytes))
        # Upscale small screenshots — Tesseract accuracy drops sharply below ~300dpi equivalent.
        if image.width < 1000:
            scale = 1000 / image.width
            image = image.resize((int(image.width * scale), int(image.height * scale)))
        image = image.convert("L")  # grayscale improves contrast-based OCR accuracy
        return pytesseract.image_to_string(image).strip()
    except Exception as e:
        raise OCRUnavailableError(f"OCR extraction failed: {e.__class__.__name__}: {e}") from e
