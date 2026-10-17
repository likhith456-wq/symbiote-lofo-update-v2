import hashlib
import json
import shutil
from pathlib import Path


_RESET_MARKER = ".app-data-reset.json"
_RESET_TARGETS = (
    "lost_found.db",
    "lost_found.db-shm",
    "lost_found.db-wal",
    "item_photos",
    "backups",
)
_RESET_CONFIRMATION = "DELETE_ALL_APP_DATA"


def reset_app_data_once(data_dir, reset_token, confirmation):
    if not reset_token:
        return False
    if confirmation != _RESET_CONFIRMATION:
        raise ValueError(
            "RESET_APP_DATA_CONFIRM must be DELETE_ALL_APP_DATA to reset application data."
        )
    if len(reset_token) < 32:
        raise ValueError("RESET_APP_DATA_TOKEN must be at least 32 characters.")

    root = Path(data_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    marker_path = root / _RESET_MARKER
    token_hash = hashlib.sha256(reset_token.encode("utf-8")).hexdigest()
    if marker_path.is_symlink():
        raise RuntimeError("Application data reset marker must not be a symlink.")
    if marker_path.exists():
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if not isinstance(marker, dict):
            raise ValueError("Application data reset marker is invalid.")
        if marker.get("token_hash") == token_hash:
            return False

    for name in _RESET_TARGETS:
        target = root / name
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)

    marker_path.write_text(
        json.dumps({"token_hash": token_hash}),
        encoding="utf-8",
    )
    return True
