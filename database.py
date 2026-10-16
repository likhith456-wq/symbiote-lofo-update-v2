import os
import re
import shutil
import sqlite3
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from security import (
    AuthorizationError,
    hash_qr_token,
    hash_password,
    roll_number_uniqueness_enabled,
    validate_roll_number,
)


SCHEMA_VERSION = 4
WORKFLOW_STATUSES = (
    "Open",
    "Under Review",
    "Claim Pending",
    "Approved for Handover",
    "Returned",
    "Closed",
)


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _backup_existing_data(db_path, backup_root, photo_dir, version):
    db_path = Path(db_path)
    backup_root = Path(backup_root)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = backup_root / f"migration-v{version}-{stamp}"
    backup_dir.mkdir(parents=True, exist_ok=False)
    backup_db = backup_dir / db_path.name

    source = sqlite3.connect(db_path)
    destination = sqlite3.connect(backup_db)
    try:
        source.backup(destination)
        integrity = destination.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError("Database backup failed its integrity check.")
    finally:
        destination.close()
        source.close()

    photo_dir = Path(photo_dir)
    backup_photos = backup_dir / "item_photos"
    if photo_dir.is_dir():
        shutil.copytree(photo_dir, backup_photos)
    else:
        backup_photos.mkdir()
    return backup_dir


@contextmanager
def connection(db_path, *, begin_immediate=False):
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 15000")
    try:
        if begin_immediate:
            conn.execute("BEGIN IMMEDIATE")
        else:
            conn.execute("BEGIN")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def _columns(conn, table):
    return {
        row["name"]
        for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }


def _add_column_if_missing(conn, table, column, declaration):
    if column not in _columns(conn, table):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {declaration}")


def _create_base_tables(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student' CHECK (role IN ('student', 'admin')),
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            status TEXT NOT NULL,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT,
            location TEXT,
            image_path TEXT,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS email_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            recipient TEXT,
            subject TEXT,
            sent_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'sent'
        )
        """
    )


def _migrate_v1(conn):
    _create_base_tables(conn)

    for column, declaration in (
        ("roll_number", "TEXT"),
        ("department", "TEXT"),
        ("year_of_study", "TEXT"),
        ("phone", "TEXT"),
    ):
        _add_column_if_missing(conn, "users", column, declaration)

    for column, declaration in (
        ("reporter_id", "INTEGER REFERENCES users(id)"),
        ("is_completed", "INTEGER NOT NULL DEFAULT 0 CHECK (is_completed IN (0, 1))"),
        ("completed_at", "TEXT"),
        ("workflow_status", "TEXT NOT NULL DEFAULT 'Open'"),
        ("status_updated_at", "TEXT"),
        ("status_updated_by", "INTEGER REFERENCES users(id)"),
    ):
        _add_column_if_missing(conn, "reports", column, declaration)

    conn.execute(
        """
        UPDATE reports
        SET workflow_status = CASE WHEN is_completed = 1 THEN 'Closed' ELSE 'Open' END
        WHERE workflow_status IS NULL OR workflow_status = ''
        """
    )
    conn.execute(
        """
        UPDATE reports
        SET workflow_status = 'Closed',
            status_updated_at = COALESCE(status_updated_at, completed_at)
        WHERE is_completed = 1 AND workflow_status = 'Open'
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS registered_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            item_name TEXT NOT NULL,
            category TEXT NOT NULL,
            detailed_description TEXT NOT NULL,
            brand_model TEXT,
            color TEXT,
            identifying_marks TEXT,
            serial_number TEXT,
            photo_path TEXT,
            created_at TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),
            qr_token_hash TEXT UNIQUE,
            qr_revoked_at TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS claims (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            found_report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE RESTRICT,
            claimant_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            lost_report_id INTEGER REFERENCES reports(id) ON DELETE SET NULL,
            ownership_evidence TEXT NOT NULL,
            submitted_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Pending'
                CHECK (status IN ('Pending', 'Approved', 'Rejected', 'Withdrawn')),
            reviewing_admin_id INTEGER REFERENCES users(id),
            reviewed_at TEXT,
            review_reason TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS handovers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            found_report_id INTEGER NOT NULL UNIQUE REFERENCES reports(id) ON DELETE RESTRICT,
            approved_claim_id INTEGER NOT NULL UNIQUE REFERENCES claims(id) ON DELETE RESTRICT,
            completed_by INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
            completed_at TEXT NOT NULL,
            notes TEXT
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_user_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            record_type TEXT NOT NULL,
            record_id INTEGER,
            created_at TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS report_status_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER NOT NULL REFERENCES reports(id) ON DELETE RESTRICT,
            old_status TEXT,
            new_status TEXT NOT NULL,
            actor_user_id INTEGER REFERENCES users(id),
            changed_at TEXT NOT NULL,
            admin_note TEXT
        )
        """
    )
    conn.execute(
        """
        INSERT INTO report_status_history(
            report_id, old_status, new_status, actor_user_id, changed_at
        )
        SELECT r.id, NULL, r.workflow_status, r.status_updated_by,
               COALESCE(r.status_updated_at, r.created_at)
        FROM reports r
        WHERE NOT EXISTS (
            SELECT 1 FROM report_status_history h WHERE h.report_id = r.id
        )
        """
    )

    for statement in (
        "CREATE INDEX IF NOT EXISTS idx_reports_reporter ON reports(reporter_id, id DESC)",
        "CREATE INDEX IF NOT EXISTS idx_reports_direction_status ON reports(status, workflow_status)",
        "CREATE INDEX IF NOT EXISTS idx_registered_owner_active ON registered_items(owner_id, is_active)",
        "CREATE INDEX IF NOT EXISTS idx_claims_found_status ON claims(found_report_id, status)",
        "CREATE INDEX IF NOT EXISTS idx_claims_claimant ON claims(claimant_user_id, submitted_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC)",
        "CREATE INDEX IF NOT EXISTS idx_status_history_report ON report_status_history(report_id, changed_at)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_one_approved_claim_per_found "
        "ON claims(found_report_id) WHERE status = 'Approved'",
    ):
        conn.execute(statement)


def _ensure_roll_number_unique_index(conn):
    if not roll_number_uniqueness_enabled():
        return
    duplicates = conn.execute(
        """
        SELECT COUNT(*) FROM (
            SELECT roll_number
            FROM users
            WHERE roll_number IS NOT NULL AND trim(roll_number) != ''
            GROUP BY roll_number
            HAVING COUNT(*) > 1
        )
        """
    ).fetchone()[0]
    if duplicates:
        raise RuntimeError(
            f"Cannot enable unique roll numbers: {duplicates} duplicate value(s) "
            "exist. Resolve them before enabling ROLL_NUMBER_UNIQUE."
        )
    conn.execute(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_unique_roll_number
        ON users(roll_number)
        WHERE roll_number IS NOT NULL AND trim(roll_number) != ''
        """
    )


def _migrate_v2(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS admin_signup_otps (
            email TEXT PRIMARY KEY,
            code_hash TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            attempts_left INTEGER NOT NULL,
            window_started_at INTEGER NOT NULL,
            send_count INTEGER NOT NULL,
            last_sent_at INTEGER NOT NULL
        )
        """
    )


def _migrate_v3(conn):
    conn.execute("DROP TABLE IF EXISTS admin_signup_otps")


def _migrate_v4(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_codes (
            email TEXT PRIMARY KEY,
            code_hash TEXT,
            expires_at INTEGER,
            attempts_left INTEGER NOT NULL,
            window_started_at INTEGER NOT NULL,
            send_count INTEGER NOT NULL,
            last_sent_at INTEGER NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS recovery_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            used_at TEXT
        )
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_recovery_codes_user "
        "ON recovery_codes(user_id, used_at)"
    )


def migrate_database(db_path, data_dir=None, *, backup=True):
    db_path = Path(db_path).resolve()
    data_dir = Path(data_dir or db_path.parent).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    db_exists = db_path.is_file() and db_path.stat().st_size > 0

    if db_exists:
        probe = sqlite3.connect(db_path)
        try:
            existing_version = probe.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
            ).fetchone()
            version = (
                probe.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
                if existing_version
                else 0
            )
        finally:
            probe.close()
    else:
        version = 0

    if version > SCHEMA_VERSION:
        raise RuntimeError(
            f"Database schema version {version} is newer than this app supports."
        )

    if version < SCHEMA_VERSION and db_exists and backup:
        _backup_existing_data(
            db_path,
            data_dir / "backups",
            data_dir / "item_photos",
            SCHEMA_VERSION,
        )

    with connection(db_path, begin_immediate=True) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        rows = conn.execute("SELECT version FROM schema_version").fetchall()
        version = max((row["version"] for row in rows), default=0)
        if version < 1:
            _migrate_v1(conn)
            conn.execute(
                "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                (1, utc_now()),
            )
            version = 1
        if version < 2:
            _migrate_v2(conn)
            conn.execute(
                "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                (2, utc_now()),
            )
            version = 2
        if version < 3:
            _migrate_v3(conn)
            conn.execute(
                "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                (3, utc_now()),
            )
            version = 3
        if version < 4:
            _migrate_v4(conn)
            conn.execute(
                "INSERT INTO schema_version(version, applied_at) VALUES (?, ?)",
                (4, utc_now()),
            )
        _ensure_roll_number_unique_index(conn)
    return SCHEMA_VERSION


def _require_user(conn, principal):
    if not principal or not principal.get("id"):
        raise AuthorizationError("Authentication is required.")
    user = conn.execute(
        "SELECT id, role FROM users WHERE id = ?",
        (principal["id"],),
    ).fetchone()
    if not user:
        raise AuthorizationError("The account is no longer available.")
    return dict(user)


def _require_admin(conn, principal, reauthenticated_at=None, *, reauth=False):
    user = _require_user(conn, principal)
    if user["role"] != "admin":
        raise AuthorizationError("Administrator access is required.")
    if reauth:
        try:
            age = time.time() - float(reauthenticated_at)
            recent = 0 <= age <= 300
        except (TypeError, ValueError):
            recent = False
        if not recent:
            raise AuthorizationError("Reauthenticate as an administrator to continue.")
    return user


def _audit(conn, actor_id, action, record_type, record_id=None):
    conn.execute(
        """
        INSERT INTO audit_log(actor_user_id, action, record_type, record_id, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_id, action, record_type, record_id, utc_now()),
    )


def _normalize_direction(direction):
    value = direction.strip().lower()
    if value in {"lost", "lost an item"}:
        return "Lost"
    if value in {"found", "found an item"}:
        return "Found"
    raise ValueError("Report direction must be Lost or Found.")


def find_user_by_email(db_path, email):
    with connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, name, email, role, created_at
            FROM users WHERE email = ?
            """,
            (email.strip().lower(),),
        ).fetchone()
    return dict(row) if row else None


def authenticate_user(db_path, email, password):
    from security import verify_password

    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            "SELECT id, name, email, password_hash, role, created_at FROM users WHERE email = ?",
            (email.strip().lower(),),
        ).fetchone()
        if not row:
            return None
        valid, needs_upgrade = verify_password(password, row["password_hash"])
        if not valid:
            return None
        if needs_upgrade:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), row["id"]),
            )
        return {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "role": row["role"],
        }


def get_authenticated_user(db_path, principal):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        row = conn.execute(
            "SELECT id, name, email, role FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
    return dict(row)


def create_student(db_path, name, email, password_hash):
    with connection(db_path, begin_immediate=True) as conn:
        conn.execute(
            """
            INSERT INTO users(name, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'student', ?)
            """,
            (name.strip(), email.strip().lower(), password_hash, utc_now()),
        )
    return find_user_by_email(db_path, email)


def create_admin(db_path, name, email, password_hash):
    email = email.strip().lower()
    with connection(db_path, begin_immediate=True) as conn:
        conn.execute(
            """
            INSERT INTO users(name, email, password_hash, role, created_at)
            VALUES (?, ?, ?, 'admin', ?)
            """,
            (name.strip(), email, password_hash, utc_now()),
        )
    return find_user_by_email(db_path, email)


def bootstrap_admin(db_path, email, password):
    if not email or not password:
        raise ValueError("Both bootstrap admin email and password are required.")
    email = email.strip().lower()
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if row:
            from security import verify_password

            existing = conn.execute(
                "SELECT password_hash FROM users WHERE id = ?",
                (row["id"],),
            ).fetchone()
            valid, _ = verify_password(password, existing["password_hash"])
            if not valid:
                raise AuthorizationError(
                    "Bootstrap credentials do not match the existing account."
                )
            conn.execute(
                "UPDATE users SET role = 'admin' WHERE id = ?",
                (row["id"],),
            )
        else:
            conn.execute(
                """
                INSERT INTO users(name, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'admin', ?)
                """,
                ("Campus administrator", email, hash_password(password), utc_now()),
            )
    return find_user_by_email(db_path, email)


def update_student_profile(db_path, principal, *, roll_number, department, year_of_study, phone):
    clean_roll = validate_roll_number(roll_number or "")
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        if clean_roll is None:
            existing = conn.execute(
                "SELECT roll_number FROM users WHERE id = ?",
                (user["id"],),
            ).fetchone()
            clean_roll = existing["roll_number"]
        department = (department or "").strip() or None
        year_of_study = (year_of_study or "").strip() or None
        phone = (phone or "").strip() or None
        if clean_roll and roll_number_uniqueness_enabled():
            duplicate = conn.execute(
                "SELECT id FROM users WHERE roll_number = ? AND id != ?",
                (clean_roll, user["id"]),
            ).fetchone()
            if duplicate:
                raise ValueError("That roll number is already registered.")
        conn.execute(
            """
            UPDATE users
            SET roll_number = ?, department = ?, year_of_study = ?, phone = ?
            WHERE id = ?
            """,
            (clean_roll, department, year_of_study, phone, user["id"]),
        )
        _audit(conn, user["id"], "profile_updated", "user", user["id"])
    return get_student_profile(db_path, principal)


def get_student_profile(db_path, principal):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        row = conn.execute(
            "SELECT id, name, email, department, year_of_study, phone FROM users WHERE id = ?",
            (user["id"],),
        ).fetchone()
    return dict(row)


def replace_recovery_codes(db_path, principal, code_hashes):
    if not code_hashes:
        raise ValueError("At least one recovery code is required.")
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        conn.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user["id"],))
        conn.executemany(
            """
            INSERT INTO recovery_codes(user_id, code_hash, created_at)
            VALUES (?, ?, ?)
            """,
            [(user["id"], code_hash, utc_now()) for code_hash in code_hashes],
        )


def count_recovery_codes(db_path, principal):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        return conn.execute(
            "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used_at IS NULL",
            (user["id"],),
        ).fetchone()[0]


def request_password_reset_code(db_path, email, code, *, now=None):
    from security import hash_password

    email = email.strip().lower()
    now = int(time.time() if now is None else now)
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            "SELECT * FROM password_reset_codes WHERE email = ?", (email,)
        ).fetchone()
        if row and now - row["window_started_at"] < 3600:
            if row["send_count"] >= 3 or now - row["last_sent_at"] < 60:
                return False
            if row["attempts_left"] <= 0:
                return False
            window_started_at = row["window_started_at"]
            send_count = row["send_count"]
            attempts_left = row["attempts_left"]
        else:
            window_started_at = now
            send_count = 0
            attempts_left = 5
        conn.execute(
            """
            INSERT INTO password_reset_codes(
                email, code_hash, expires_at, attempts_left,
                window_started_at, send_count, last_sent_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(email) DO UPDATE SET
                code_hash = excluded.code_hash,
                expires_at = excluded.expires_at,
                attempts_left = excluded.attempts_left,
                window_started_at = excluded.window_started_at,
                send_count = excluded.send_count,
                last_sent_at = excluded.last_sent_at
            """,
            (
                email,
                hash_password(code),
                now + 600,
                attempts_left,
                window_started_at,
                send_count + 1,
                now,
            ),
        )
    return True


def invalidate_password_reset_code(db_path, email, code):
    from security import verify_password

    email = email.strip().lower()
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            "SELECT code_hash FROM password_reset_codes WHERE email = ?", (email,)
        ).fetchone()
        if row and row["code_hash"] and verify_password(code, row["code_hash"])[0]:
            conn.execute(
                """
                UPDATE password_reset_codes
                SET code_hash = NULL, expires_at = NULL
                WHERE email = ?
                """,
                (email,),
            )


def reset_password(db_path, email, credential, password_hash, *, method, now=None):
    from security import verify_password

    if method not in {"email", "recovery"}:
        raise ValueError("Password reset method must be email or recovery.")
    email = email.strip().lower()
    now = int(time.time() if now is None else now)
    with connection(db_path, begin_immediate=True) as conn:
        reset = conn.execute(
            "SELECT * FROM password_reset_codes WHERE email = ?", (email,)
        ).fetchone()
        if reset and now - reset["window_started_at"] < 3600:
            attempts_left = reset["attempts_left"]
            window_started_at = reset["window_started_at"]
        else:
            attempts_left = 5
            window_started_at = now
        if attempts_left <= 0:
            return False

        user = conn.execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        code_record = None
        if method == "email" and reset and reset["code_hash"] and now < reset["expires_at"]:
            valid = verify_password(credential, reset["code_hash"])[0]
        elif method == "recovery" and user:
            for candidate in conn.execute(
                """
                SELECT id, code_hash FROM recovery_codes
                WHERE user_id = ? AND used_at IS NULL
                """,
                (user["id"],),
            ).fetchall():
                if verify_password(credential, candidate["code_hash"])[0]:
                    valid = True
                    code_record = candidate
                    break
            else:
                valid = False
        else:
            valid = False

        if not user or not valid:
            conn.execute(
                """
                INSERT INTO password_reset_codes(
                    email, code_hash, expires_at, attempts_left,
                    window_started_at, send_count, last_sent_at
                ) VALUES (?, NULL, NULL, ?, ?, 0, 0)
                ON CONFLICT(email) DO UPDATE SET
                    attempts_left = excluded.attempts_left,
                    window_started_at = excluded.window_started_at
                """,
                (email, attempts_left - 1, window_started_at),
            )
            return False

        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user["id"]),
        )
        if code_record:
            conn.execute(
                "UPDATE recovery_codes SET used_at = ? WHERE id = ?",
                (utc_now(), code_record["id"]),
            )
        if reset:
            conn.execute(
                """
                UPDATE password_reset_codes
                SET code_hash = NULL, expires_at = NULL
                WHERE email = ?
                """,
                (email,),
            )
        else:
            conn.execute(
                """
                INSERT INTO password_reset_codes(
                    email, code_hash, expires_at, attempts_left,
                    window_started_at, send_count, last_sent_at
                ) VALUES (?, NULL, NULL, ?, ?, 0, 0)
                """,
                (email, attempts_left, window_started_at),
            )
        _audit(conn, user["id"], "password_reset", "user", user["id"])
    return True


def admin_search_students_by_roll(db_path, principal, roll_number, reauthenticated_at):
    roll_number = (roll_number or "").strip()
    if not roll_number:
        return []
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal, reauthenticated_at, reauth=True)
        rows = conn.execute(
            """
            SELECT id, name, email, roll_number, department, year_of_study, phone
            FROM users WHERE roll_number = ?
            """,
            (roll_number,),
        ).fetchall()
        _audit(conn, admin["id"], "roll_number_search", "user", None)
    return [dict(row) for row in rows]


def save_report(db_path, principal, direction, item_name, category, description, location, image_path):
    direction = _normalize_direction(direction)
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        cursor = conn.execute(
            """
            INSERT INTO reports(
                reporter_id, status, item_name, category, description, location,
                image_path, created_at, workflow_status, status_updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?)
            """,
            (
                user["id"], direction, item_name.strip(), category.strip(),
                description.strip(), location.strip(), image_path, utc_now(), utc_now(),
            ),
        )
        report_id = cursor.lastrowid
        conn.execute(
            """
            INSERT INTO report_status_history(report_id, old_status, new_status, actor_user_id, changed_at)
            VALUES (?, NULL, 'Open', ?, ?)
            """,
            (report_id, user["id"], utc_now()),
        )
    return report_id


def log_email(db_path, report_id, recipient, subject, status):
    if status not in {"sent", "failed"}:
        raise ValueError("Email log status must be sent or failed.")
    with connection(db_path) as conn:
        conn.execute(
            """
            INSERT INTO email_log(report_id, recipient, subject, sent_at, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (report_id, recipient, subject, utc_now(), status),
        )


def save_public_found_report(db_path, item_name, description, location):
    with connection(db_path, begin_immediate=True) as conn:
        cursor = conn.execute(
            """
            INSERT INTO reports(
                reporter_id, status, item_name, category, description, location,
                created_at, workflow_status, status_updated_at
            ) VALUES (NULL, 'Found', ?, 'Other', ?, ?, ?, 'Open', ?)
            """,
            (item_name, description, location, utc_now(), utc_now()),
        )
        report_id = cursor.lastrowid
        conn.execute(
            """
            INSERT INTO report_status_history(report_id, old_status, new_status, changed_at)
            VALUES (?, NULL, 'Open', ?)
            """,
            (report_id, utc_now()),
        )
    return report_id


REPORT_COLUMNS = (
    "id, reporter_id, status, item_name, category, description, location, "
    "image_path, created_at, is_completed, completed_at, workflow_status, "
    "status_updated_at"
)


def list_reports(db_path, principal, *, own_only=False, admin=False, reauthenticated_at=None):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        if admin:
            _require_admin(conn, principal, reauthenticated_at, reauth=True)
            rows = conn.execute(
                """
                SELECT r.id, r.reporter_id, r.status, r.item_name, r.category,
                       r.description, r.location, r.image_path, r.created_at,
                       r.is_completed, r.completed_at, r.workflow_status,
                       r.status_updated_at, u.name AS reporter_name
                FROM reports r
                """
                "LEFT JOIN users u ON u.id = r.reporter_id ORDER BY r.id DESC"
            ).fetchall()
        elif own_only:
            rows = conn.execute(
                f"SELECT {REPORT_COLUMNS}, 1 AS is_owner FROM reports "
                "WHERE reporter_id = ? ORDER BY id DESC",
                (user["id"],),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT id, status, item_name, category, description, location,
                       image_path, created_at, is_completed, completed_at,
                       workflow_status, status_updated_at,
                       reporter_id = ? AS is_owner
                FROM reports ORDER BY id DESC
                """,
                (user["id"],),
            ).fetchall()
    return [dict(row) for row in rows]


def get_report_for_user(db_path, principal, report_id):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        row = conn.execute(
            f"SELECT {REPORT_COLUMNS} FROM reports WHERE id = ? AND reporter_id = ?",
            (report_id, user["id"]),
        ).fetchone()
    return dict(row) if row else None


def _require_report_found(conn, report_id):
    row = conn.execute(
        "SELECT id, status, workflow_status, is_completed FROM reports WHERE id = ?",
        (report_id,),
    ).fetchone()
    if not row or _normalize_direction(row["status"]) != "Found":
        raise ValueError("Claims can only be made against an existing Found report.")
    return dict(row)


def find_duplicate_reports(
    db_path,
    principal,
    direction,
    item_name,
    category,
    description,
    location,
    cutoff_iso,
):
    direction = _normalize_direction(direction)
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        rows = conn.execute(
            f"""
            SELECT id, status, item_name, category, description, location,
                   image_path, created_at, is_completed, completed_at,
                   workflow_status, status_updated_at, 1 AS is_owner
            FROM reports
            WHERE reporter_id = ? AND status = ? AND created_at >= ?
            ORDER BY id DESC
            """,
            (user["id"], direction, cutoff_iso),
        ).fetchall()
    candidates = []
    incoming = _token_set(" ".join((item_name, category, description, location)))
    for row in rows:
        item = dict(row)
        prior = _token_set(
            " ".join(
                (
                    item["item_name"] or "",
                    item["category"] or "",
                    item["description"] or "",
                    item["location"] or "",
                )
            )
        )
        similarity = len(incoming & prior) / max(1, len(incoming | prior))
        if similarity >= 0.25 or (
            (item["item_name"] or "").casefold() == item_name.casefold()
            and (item["location"] or "").casefold() == location.casefold()
        ):
            item["duplicate_similarity"] = similarity
            candidates.append(item)
    return candidates


def _token_set(text):
    return set(re.findall(r"[a-z0-9]+", text.casefold()))


def mark_report_completed(db_path, principal, report_id):
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        if user["role"] == "admin":
            cursor = conn.execute(
                """
                UPDATE reports
                SET is_completed = 1, completed_at = ?, workflow_status = 'Closed',
                    status_updated_at = ?, status_updated_by = ?
                WHERE id = ? AND is_completed = 0
                """,
                (utc_now(), utc_now(), user["id"], report_id),
            )
        else:
            cursor = conn.execute(
                """
                UPDATE reports
                SET is_completed = 1, completed_at = ?, workflow_status = 'Closed',
                    status_updated_at = ?, status_updated_by = ?
                WHERE id = ? AND reporter_id = ? AND is_completed = 0
                """,
                (utc_now(), utc_now(), user["id"], report_id, user["id"]),
            )
        if cursor.rowcount:
            conn.execute(
                """
                INSERT INTO report_status_history(report_id, old_status, new_status, actor_user_id, changed_at)
                VALUES (?, 'Open', 'Closed', ?, ?)
                """,
                (report_id, user["id"], utc_now()),
            )
    return cursor.rowcount > 0


def update_workflow_status(db_path, principal, report_id, new_status, note=""):
    if new_status not in WORKFLOW_STATUSES or new_status in {"Returned", "Approved for Handover"}:
        raise ValueError("That workflow status can only be set by claim or handover actions.")
    allowed = {
        "Open": {"Under Review", "Claim Pending", "Closed"},
        "Under Review": {"Open", "Claim Pending", "Closed"},
        "Claim Pending": {"Under Review", "Closed"},
        "Approved for Handover": {"Under Review", "Closed"},
        "Returned": {"Closed"},
        "Closed": set(),
    }
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal)
        row = conn.execute(
            "SELECT workflow_status FROM reports WHERE id = ?",
            (report_id,),
        ).fetchone()
        if not row:
            raise ValueError("Report does not exist.")
        old_status = row["workflow_status"]
        if new_status not in allowed.get(old_status, set()):
            raise ValueError(f"Cannot change workflow status from {old_status} to {new_status}.")
        conn.execute(
            """
            UPDATE reports
            SET workflow_status = ?, status_updated_at = ?, status_updated_by = ?
            WHERE id = ?
            """,
            (new_status, utc_now(), admin["id"], report_id),
        )
        conn.execute(
            """
            INSERT INTO report_status_history(
                report_id, old_status, new_status, actor_user_id, changed_at, admin_note
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (report_id, old_status, new_status, admin["id"], utc_now(), note.strip() or None),
        )
        _audit(conn, admin["id"], "workflow_status_changed", "report", report_id)


def get_status_history(db_path, principal, report_id, *, admin=False, reauthenticated_at=None):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        if admin:
            _require_admin(conn, principal, reauthenticated_at, reauth=True)
            rows = conn.execute(
                """
                SELECT h.*, u.name AS actor_name
                FROM report_status_history h
                LEFT JOIN users u ON u.id = h.actor_user_id
                WHERE h.report_id = ? ORDER BY h.id
                """,
                (report_id,),
            ).fetchall()
        else:
            owns = conn.execute(
                "SELECT 1 FROM reports WHERE id = ? AND reporter_id = ?",
                (report_id, user["id"]),
            ).fetchone()
            if not owns:
                raise AuthorizationError("You may only view the status history for your own reports.")
            rows = conn.execute(
                """
                SELECT id, report_id, old_status, new_status, changed_at
                FROM report_status_history WHERE report_id = ? ORDER BY id
                """,
                (report_id,),
            ).fetchall()
    return [dict(row) for row in rows]


def _require_owner_or_admin(conn, principal, owner_id, reauthenticated_at=None):
    user = _require_user(conn, principal)
    if user["role"] == "admin":
        _require_admin(conn, principal, reauthenticated_at, reauth=True)
        return user
    if user["id"] != owner_id:
        raise AuthorizationError("You do not have access to this private item.")
    return user


def create_registered_item(
    db_path,
    principal,
    *,
    item_name,
    category,
    detailed_description,
    brand_model="",
    color="",
    identifying_marks="",
    serial_number="",
    photo_path=None,
    qr_token_hash,
):
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        cursor = conn.execute(
            """
            INSERT INTO registered_items(
                owner_id, item_name, category, detailed_description, brand_model,
                color, identifying_marks, serial_number, photo_path, created_at,
                qr_token_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user["id"], item_name.strip(), category.strip(),
                detailed_description.strip(), brand_model.strip() or None,
                color.strip() or None, identifying_marks.strip() or None,
                serial_number.strip() or None, photo_path, utc_now(), qr_token_hash,
            ),
        )
        item_id = cursor.lastrowid
        _audit(conn, user["id"], "registered_item_created", "registered_item", item_id)
    return item_id


def rotate_registered_item_qr(db_path, principal, item_id, token, reauthenticated_at=None):
    token_hash = hash_qr_token(token)
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            "SELECT owner_id, is_active FROM registered_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if not row or not row["is_active"]:
            raise ValueError("This registered item is not active.")
        user = _require_owner_or_admin(conn, principal, row["owner_id"], reauthenticated_at)
        conn.execute(
            """
            UPDATE registered_items SET qr_token_hash = ?, qr_revoked_at = NULL
            WHERE id = ?
            """,
            (token_hash, item_id),
        )
        _audit(conn, user["id"], "registered_item_qr_rotated", "registered_item", item_id)
    return True


REGISTERED_PRIVATE_COLUMNS = (
    "id, owner_id, item_name, category, detailed_description, brand_model, "
    "color, identifying_marks, serial_number, photo_path, created_at, "
    "is_active, qr_revoked_at"
)


def list_registered_items(db_path, principal, *, owner_id=None, reauthenticated_at=None):
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        if user["role"] == "admin":
            _require_admin(conn, principal, reauthenticated_at, reauth=True)
            rows = conn.execute(
                f"SELECT {REGISTERED_PRIVATE_COLUMNS} FROM registered_items ORDER BY id DESC"
            ).fetchall()
            for row in rows:
                _audit(conn, user["id"], "private_registered_item_accessed", "registered_item", row["id"])
        else:
            if owner_id is not None and owner_id != user["id"]:
                raise AuthorizationError("You may only access your own registered items.")
            rows = conn.execute(
                f"""
                SELECT {REGISTERED_PRIVATE_COLUMNS}
                FROM registered_items WHERE owner_id = ? ORDER BY id DESC
                """,
                (user["id"],),
            ).fetchall()
    return [dict(row) for row in rows]


def get_registered_item(db_path, principal, item_id, reauthenticated_at=None):
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            f"SELECT {REGISTERED_PRIVATE_COLUMNS} FROM registered_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if not row:
            return None
        user = _require_owner_or_admin(conn, principal, row["owner_id"], reauthenticated_at)
        if user["role"] == "admin":
            _audit(conn, user["id"], "private_registered_item_accessed", "registered_item", item_id)
    return dict(row)


def lookup_public_qr(db_path, token):
    if not token or len(token) > 256:
        return False
    token_hash = hash_qr_token(token)
    with connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM registered_items
            WHERE qr_token_hash = ? AND is_active = 1 AND qr_revoked_at IS NULL
            """,
            (token_hash,),
        ).fetchone()
    return row is not None


def admin_lookup_qr(db_path, principal, token, reauthenticated_at):
    token_hash = hash_qr_token(token or "")
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal, reauthenticated_at, reauth=True)
        row = conn.execute(
            f"""
            SELECT i.{REGISTERED_PRIVATE_COLUMNS.replace(", ", ", i.")},
                   u.name AS owner_name, u.email AS owner_email,
                   u.roll_number AS owner_roll_number, u.department AS owner_department,
                   u.year_of_study AS owner_year_of_study, u.phone AS owner_phone
            FROM registered_items i
            JOIN users u ON u.id = i.owner_id
            WHERE i.qr_token_hash = ?
            """,
            (token_hash,),
        ).fetchone()
        if row:
            _audit(conn, admin["id"], "private_registered_item_accessed", "registered_item", row["id"])
    return dict(row) if row else None


def revoke_registered_item_qr(db_path, principal, item_id, reauthenticated_at=None):
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            "SELECT owner_id FROM registered_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if not row:
            return False
        user = _require_owner_or_admin(conn, principal, row["owner_id"], reauthenticated_at)
        conn.execute(
            "UPDATE registered_items SET qr_token_hash = NULL, qr_revoked_at = ? WHERE id = ?",
            (utc_now(), item_id),
        )
        _audit(conn, user["id"], "registered_item_qr_revoked", "registered_item", item_id)
    return True


def deactivate_registered_item(db_path, principal, item_id, reauthenticated_at=None):
    with connection(db_path, begin_immediate=True) as conn:
        row = conn.execute(
            "SELECT owner_id FROM registered_items WHERE id = ?",
            (item_id,),
        ).fetchone()
        if not row:
            return False
        user = _require_owner_or_admin(conn, principal, row["owner_id"], reauthenticated_at)
        conn.execute(
            "UPDATE registered_items SET is_active = 0 WHERE id = ?",
            (item_id,),
        )
        conn.execute(
            "UPDATE registered_items SET qr_token_hash = NULL, qr_revoked_at = ? WHERE id = ?",
            (utc_now(), item_id),
        )
        _audit(conn, user["id"], "registered_item_deactivated", "registered_item", item_id)
    return True


def create_claim(db_path, principal, found_report_id, ownership_evidence, lost_report_id=None):
    if not ownership_evidence or not ownership_evidence.strip():
        raise ValueError("Please provide private ownership evidence.")
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        if user["role"] != "student":
            raise AuthorizationError("Only student accounts can submit claims.")
        report = _require_report_found(conn, found_report_id)
        if report["is_completed"] or report["workflow_status"] in {"Returned", "Closed"}:
            raise ValueError("This Found report is already closed.")
        if lost_report_id is not None:
            lost = conn.execute(
                "SELECT reporter_id, status FROM reports WHERE id = ?",
                (lost_report_id,),
            ).fetchone()
            if (
                not lost
                or lost["reporter_id"] != user["id"]
                or _normalize_direction(lost["status"]) != "Lost"
            ):
                raise ValueError("Linked Lost report must be one of your own Lost reports.")
        cursor = conn.execute(
            """
            INSERT INTO claims(
                found_report_id, claimant_user_id, lost_report_id,
                ownership_evidence, submitted_at, status
            ) VALUES (?, ?, ?, ?, ?, 'Pending')
            """,
            (found_report_id, user["id"], lost_report_id, ownership_evidence.strip(), utc_now()),
        )
        claim_id = cursor.lastrowid
        old_status = report["workflow_status"]
        if old_status in {"Open", "Under Review"}:
            conn.execute(
                """
                UPDATE reports SET workflow_status = 'Claim Pending',
                    status_updated_at = ?, status_updated_by = ?
                WHERE id = ?
                """,
                (utc_now(), user["id"], found_report_id),
            )
            conn.execute(
                """
                INSERT INTO report_status_history(
                    report_id, old_status, new_status, actor_user_id, changed_at
                ) VALUES (?, ?, 'Claim Pending', ?, ?)
                """,
                (found_report_id, old_status, user["id"], utc_now()),
            )
        _audit(conn, user["id"], "claim_submitted", "claim", claim_id)
    return claim_id


def list_my_claims(db_path, principal):
    with connection(db_path) as conn:
        user = _require_user(conn, principal)
        rows = conn.execute(
            """
            SELECT c.id, c.found_report_id, c.claimant_user_id, c.lost_report_id,
                   c.ownership_evidence, c.submitted_at, c.status, c.reviewed_at,
                   c.review_reason, r.item_name, r.category, r.location
            FROM claims c JOIN reports r ON r.id = c.found_report_id
            WHERE c.claimant_user_id = ? ORDER BY c.id DESC
            """,
            (user["id"],),
        ).fetchall()
    return [dict(row) for row in rows]


def list_admin_claims(db_path, principal, reauthenticated_at):
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal, reauthenticated_at, reauth=True)
        rows = conn.execute(
            """
            SELECT c.*, r.item_name, r.category, r.location,
                   u.name AS claimant_name, u.email AS claimant_email
            FROM claims c
            JOIN reports r ON r.id = c.found_report_id
            JOIN users u ON u.id = c.claimant_user_id
            ORDER BY c.id DESC
            """
        ).fetchall()
        for row in rows:
            _audit(conn, admin["id"], "private_claim_evidence_accessed", "claim", row["id"])
    return [dict(row) for row in rows]


def review_claim(db_path, principal, claim_id, decision, reason, reauthenticated_at):
    if decision not in {"Approved", "Rejected"}:
        raise ValueError("Admin decision must be Approved or Rejected.")
    if not reason or not reason.strip():
        raise ValueError("A decision reason is required.")
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal, reauthenticated_at, reauth=True)
        claim = conn.execute(
            """
            SELECT c.id, c.found_report_id, c.status, r.status AS direction,
                   r.workflow_status, r.is_completed
            FROM claims c JOIN reports r ON r.id = c.found_report_id
            WHERE c.id = ?
            """,
            (claim_id,),
        ).fetchone()
        if not claim or claim["status"] != "Pending":
            raise ValueError("Claim is missing or no longer pending.")
        if _normalize_direction(claim["direction"]) != "Found" or claim["is_completed"]:
            raise ValueError("The Found report is not available for claim review.")
        if decision == "Approved":
            existing = conn.execute(
                "SELECT id FROM claims WHERE found_report_id = ? AND status = 'Approved'",
                (claim["found_report_id"],),
            ).fetchone()
            if existing:
                raise ValueError("Another claim is already approved for this Found report.")
        conn.execute(
            """
            UPDATE claims SET status = ?, reviewing_admin_id = ?, reviewed_at = ?,
                review_reason = ? WHERE id = ? AND status = 'Pending'
            """,
            (decision, admin["id"], utc_now(), reason.strip(), claim_id),
        )
        if decision == "Approved":
            target_status = "Approved for Handover"
        else:
            pending = conn.execute(
                """
                SELECT 1 FROM claims
                WHERE found_report_id = ? AND id != ? AND status = 'Pending'
                LIMIT 1
                """,
                (claim["found_report_id"], claim_id),
            ).fetchone()
            target_status = "Claim Pending" if pending else "Under Review"
        conn.execute(
            """
            UPDATE reports SET workflow_status = ?, status_updated_at = ?,
                status_updated_by = ?,
                is_completed = CASE WHEN ? = 'Closed' THEN 1 ELSE is_completed END,
                completed_at = CASE WHEN ? = 'Closed' THEN ? ELSE completed_at END
            WHERE id = ?
            """,
            (
                target_status,
                utc_now(),
                admin["id"],
                target_status,
                target_status,
                utc_now(),
                claim["found_report_id"],
            ),
        )
        conn.execute(
            """
            INSERT INTO report_status_history(
                report_id, old_status, new_status, actor_user_id, changed_at, admin_note
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                claim["found_report_id"], claim["workflow_status"], target_status,
                admin["id"], utc_now(), reason.strip(),
            ),
        )
        _audit(conn, admin["id"], f"claim_{decision.lower()}", "claim", claim_id)


def complete_handover(db_path, principal, claim_id, notes, reauthenticated_at):
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal, reauthenticated_at, reauth=True)
        claim = conn.execute(
            """
            SELECT c.id, c.found_report_id, c.status, r.status AS direction,
                   r.workflow_status, r.is_completed
            FROM claims c JOIN reports r ON r.id = c.found_report_id
            WHERE c.id = ?
            """,
            (claim_id,),
        ).fetchone()
        if (
            not claim
            or claim["status"] != "Approved"
            or claim["workflow_status"] != "Approved for Handover"
            or claim["is_completed"]
            or _normalize_direction(claim["direction"]) != "Found"
        ):
            raise ValueError("Only an approved claim for an open Found report can be handed over.")
        now = utc_now()
        conn.execute(
            """
            INSERT INTO handovers(found_report_id, approved_claim_id, completed_by, completed_at, notes)
            VALUES (?, ?, ?, ?, ?)
            """,
            (claim["found_report_id"], claim_id, admin["id"], now, notes.strip() or None),
        )
        conn.execute(
            """
            UPDATE reports SET workflow_status = 'Returned', is_completed = 1,
                completed_at = ?, status_updated_at = ?, status_updated_by = ?
            WHERE id = ? AND is_completed = 0
            """,
            (now, now, admin["id"], claim["found_report_id"]),
        )
        conn.execute(
            """
            INSERT INTO report_status_history(
                report_id, old_status, new_status, actor_user_id, changed_at
            ) VALUES (?, 'Approved for Handover', 'Returned', ?, ?)
            """,
            (claim["found_report_id"], admin["id"], now),
        )
        conn.execute(
            """
            UPDATE claims SET status = 'Rejected', reviewing_admin_id = ?,
                reviewed_at = ?, review_reason = 'Another claim completed handover.'
            WHERE found_report_id = ? AND status = 'Pending'
            """,
            (admin["id"], now, claim["found_report_id"]),
        )
        _audit(conn, admin["id"], "handover_completed", "handover", claim["found_report_id"])
    return True


def withdraw_claim(db_path, principal, claim_id):
    with connection(db_path, begin_immediate=True) as conn:
        user = _require_user(conn, principal)
        cursor = conn.execute(
            """
            UPDATE claims SET status = 'Withdrawn'
            WHERE id = ? AND claimant_user_id = ? AND status = 'Pending'
            """,
            (claim_id, user["id"]),
        )
        if cursor.rowcount:
            _audit(conn, user["id"], "claim_withdrawn", "claim", claim_id)
    return cursor.rowcount > 0


def admin_search_claimants_by_roll(db_path, principal, roll_number, reauthenticated_at):
    roll_number = (roll_number or "").strip()
    if not roll_number:
        return []
    with connection(db_path, begin_immediate=True) as conn:
        admin = _require_admin(conn, principal, reauthenticated_at, reauth=True)
        rows = conn.execute(
            """
            SELECT id, name, email, roll_number, department, year_of_study, phone
            FROM users WHERE roll_number = ?
            """,
            (roll_number,),
        ).fetchall()
        _audit(conn, admin["id"], "roll_number_search", "user", None)
    return [dict(row) for row in rows]


def list_audit_log(db_path, principal, reauthenticated_at):
    with connection(db_path, begin_immediate=True) as conn:
        _require_admin(conn, principal, reauthenticated_at, reauth=True)
        rows = conn.execute(
            """
            SELECT id, actor_user_id, action, record_type, record_id, created_at
            FROM audit_log ORDER BY id DESC LIMIT 500
            """
        ).fetchall()
    return [dict(row) for row in rows]
