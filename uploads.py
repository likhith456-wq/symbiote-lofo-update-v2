import io
import os
import uuid
from pathlib import Path

from PIL import Image, UnidentifiedImageError


# Allow very large images by default while preserving environment overrides.
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(1 << 40)))
MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", str(1 << 52)))
ALLOWED_IMAGE_FORMATS = {"JPEG", "PNG", "WEBP"}


def save_uploaded_image(uploaded_file, target_dir):
    if uploaded_file is None:
        return None
    payload = uploaded_file.getvalue()
    if not payload:
        raise ValueError("The selected image file is empty.")
    if len(payload) > MAX_UPLOAD_BYTES:
        raise ValueError(f"Image must be smaller than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")

    try:
        with Image.open(io.BytesIO(payload)) as source:
            if source.format not in ALLOWED_IMAGE_FORMATS:
                raise ValueError("Use a JPEG, PNG, or WebP image.")
            if source.width * source.height > MAX_IMAGE_PIXELS:
                raise ValueError("Image dimensions are too large.")
            source.verify()
        with Image.open(io.BytesIO(payload)) as source:
            image = source.convert("RGB")
    except (UnidentifiedImageError, OSError) as error:
        raise ValueError("The uploaded file is not a valid image.") from error

    target_dir = Path(target_dir).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    path = (target_dir / f"{uuid.uuid4().hex}.jpg").resolve()
    if path.parent != target_dir:
        raise ValueError("Invalid upload destination.")
    image.save(path, format="JPEG", quality=88, optimize=True)
    return str(path)


def build_qr_payload(base_url, token):
    from urllib.parse import urlsplit, urlunsplit

    if not base_url:
        raise ValueError("Set APP_BASE_URL before generating downloadable QR codes.")
    parsed = urlsplit(base_url.strip())
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("APP_BASE_URL must be a trusted absolute HTTP(S) URL without credentials, query, or fragment.")
    if parsed.scheme != "https" and parsed.hostname not in {"localhost", "127.0.0.1"}:
        raise ValueError("APP_BASE_URL must use HTTPS except for local development.")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/") + "/", "qr=" + token, ""))


def make_qr_png(payload):
    import qrcode

    image = qrcode.make(payload)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()
