import io
import os
import re
import subprocess
import unicodedata
from datetime import date
from difflib import SequenceMatcher

from PIL import Image, ImageOps, UnidentifiedImageError

from security import meets_minimum_age


MAX_DOCUMENT_BYTES = int(os.getenv("MAX_DOCUMENT_BYTES", str(1 << 40)))
MAX_DOCUMENT_PIXELS = int(os.getenv("MAX_DOCUMENT_PIXELS", str(1 << 52)))
DATE_PATTERNS = (
    re.compile(r"(?<!\d)(\d{1,2})[/-](\d{1,2})[/-](\d{4})(?!\d)"),
    re.compile(r"(?<!\d)(\d{4})-(\d{1,2})-(\d{1,2})(?!\d)"),
)
DOB_LABEL = re.compile(
    r"\b(?:date\s+of\s+birth|dob|d\s*\.?\s*o\s*\.?\s*b|born)\b",
    re.IGNORECASE,
)


class IdentityOCRUnavailable(RuntimeError):
    pass


def _image_as_png(image_bytes):
    if not image_bytes or len(image_bytes) > MAX_DOCUMENT_BYTES:
        raise ValueError("Choose an image smaller than 8 MB.")
    try:
        with Image.open(io.BytesIO(image_bytes)) as source:
            if source.format not in {"JPEG", "PNG", "WEBP"}:
                raise ValueError("Use a JPEG, PNG, or WebP image.")
            if source.width * source.height > MAX_DOCUMENT_PIXELS:
                raise ValueError("The image dimensions are too large.")
            image = ImageOps.exif_transpose(source).convert("RGB")
    except (UnidentifiedImageError, OSError) as error:
        raise ValueError("The uploaded file is not a valid image.") from error

    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def extract_text_in_memory(image_bytes, *, command="tesseract", timeout=20):
    png_bytes = _image_as_png(image_bytes)
    try:
        result = subprocess.run(
            [command, "stdin", "stdout", "--psm", "6", "-l", "eng"],
            input=png_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise IdentityOCRUnavailable(
            "Local OCR is unavailable. Install Tesseract OCR and restart the app."
        ) from error
    except subprocess.TimeoutExpired as error:
        raise IdentityOCRUnavailable(
            "Local OCR timed out. Try a clearer, smaller image."
        ) from error
    except subprocess.CalledProcessError as error:
        raise IdentityOCRUnavailable(
            "Local OCR could not read this image. Try a clearer photo."
        ) from error
    except OSError as error:
        raise IdentityOCRUnavailable(
            "The local OCR process could not be started."
        ) from error
    return result.stdout.decode("utf-8", errors="replace")


def _parse_date(match, pattern_index):
    parts = [int(part) for part in match.groups()]
    if pattern_index == 0:
        day, month, year = parts
    else:
        year, month, day = parts
    try:
        return date(year, month, day)
    except ValueError:
        return None


def extract_labeled_date_of_birth(text):
    candidates = []
    for pattern_index, pattern in enumerate(DATE_PATTERNS):
        for match in pattern.finditer(text):
            preceding_text = text[max(0, match.start() - 60):match.start()]
            labels = list(DOB_LABEL.finditer(preceding_text))
            if labels and len(preceding_text) - labels[-1].end() <= 45:
                parsed = _parse_date(match, pattern_index)
                if parsed:
                    candidates.append((match.start(), parsed))
    if not candidates:
        return None
    candidates.sort(key=lambda candidate: candidate[0])
    return candidates[0][1]


def _normalize_name(value):
    normalized = unicodedata.normalize("NFKD", value).casefold()
    return " ".join(
        "".join(char for char in normalized if not unicodedata.combining(char))
        .replace("\n", " ")
        .split()
    )


def name_appears_in_text(name, text):
    expected = _normalize_name(name)
    tokens = re.findall(r"[^\W_]+", expected, flags=re.UNICODE)
    if not tokens or len(expected) < 3:
        return False
    document_tokens = re.findall(
        r"[^\W_]+",
        _normalize_name(text),
        flags=re.UNICODE,
    )
    width = len(tokens)
    expected_phrase = " ".join(tokens)
    return any(
        SequenceMatcher(
            None,
            expected_phrase,
            " ".join(document_tokens[index:index + width]),
        ).ratio() >= 0.92
        for index in range(max(0, len(document_tokens) - width + 1))
    )


def verify_document_text(text, full_name, date_of_birth):
    document_dob = extract_labeled_date_of_birth(text)
    return {
        "name_matches": name_appears_in_text(full_name, text),
        "date_of_birth_matches": document_dob == date_of_birth,
        "meets_minimum_age": (
            meets_minimum_age(document_dob, 23)
            if document_dob
            else False
        ),
    }


def check_identity_document(image_bytes, full_name, date_of_birth, *, command="tesseract"):
    text = extract_text_in_memory(image_bytes, command=command)
    return verify_document_text(text, full_name, date_of_birth)
