import os
import re
import smtplib
import time
from datetime import date, datetime, timedelta
from pathlib import Path

import pandas as pd
import streamlit as st
import torch
from PIL import Image
from transformers import pipeline

import database as db
from catalog import CATEGORIES, ITEMS, identify_from_text
from identity_ocr import IdentityOCRUnavailable, check_identity_document
from matching import rank_lost_found_matches
from security import (
    AuthorizationError,
    create_qr_token,
    create_recovery_codes,
    hash_password,
    hash_qr_token,
    is_under_age,
    meets_minimum_age,
)
from uploads import build_qr_payload, make_qr_png, save_uploaded_image


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("APP_DATA_DIR", str(APP_DIR))).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "lost_found.db"
UPLOAD_DIR = DATA_DIR / "item_photos"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
SESSION_IDLE_SECONDS = max(300, int(os.getenv("SESSION_IDLE_SECONDS", "1800")))
ALLOWED_STATUS = list(db.WORKFLOW_STATUSES)

st.set_page_config(
    page_title="Symbiote Lofo AI",
    page_icon="🔎",
    layout="wide",
)


def apply_theme():
    st.markdown(
        """
        <style>
        :root {
            --crimson: #b2183a;
            --crimson-bright: #dc4660;
            --green: #2e9b57;
            --green-bright: #58bd79;
            --surface: #191d18;
            --text: #f4f2ed;
        }
        html, body, [data-testid="stAppViewContainer"] {
            background: linear-gradient(135deg, #17100f, #211518 48%, #111b14);
            color: var(--text);
        }
        .stApp { background: transparent; }
        .block-container { padding-top: 2rem; padding-bottom: 2rem; }
        div[data-testid="stSidebar"] {
            background: rgba(23, 18, 18, 0.96);
            border-right: 1px solid rgba(255,255,255,0.06);
        }
        [data-testid="stButton"] > button {
            border: 0;
            border-radius: 12px;
            background: linear-gradient(135deg, var(--green), var(--green-bright));
            color: #07160c;
            font-weight: 700;
        }
        [data-testid="stFormSubmitButton"] > button {
            border-radius: 12px;
            background: linear-gradient(135deg, var(--crimson), var(--crimson-bright));
            color: #fff;
            font-weight: 700;
        }
        [data-testid="stButton"] > button:hover,
        [data-testid="stFormSubmitButton"] > button:hover { filter: brightness(1.08); }
        div[data-testid="stAlert"] { border-radius: 12px; }
        .stTabs [role="tab"] {
            background: rgba(255,255,255,0.04);
            border-radius: 8px 8px 0 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


@st.cache_resource
def prepare_database(db_path, data_dir):
    db.migrate_database(db_path, data_dir)
    return True


@st.cache_resource
def load_model():
    return pipeline(
        task="zero-shot-image-classification",
        model=os.getenv("IMAGE_MODEL", "openai/clip-vit-base-patch32"),
        device=-1,
    )


@st.cache_data(show_spinner=False)
def get_image_embedding(path, modified_at):
    safe_path = Path(path).resolve()
    if not safe_path.is_file():
        return None
    image_root = UPLOAD_DIR.resolve()
    if image_root not in safe_path.parents:
        raise ValueError("Report photo path is outside the configured upload directory.")
    classifier = load_model()
    with Image.open(safe_path) as source:
        image = source.convert("RGB")
    inputs = classifier.image_processor(images=image, return_tensors="pt")
    classifier.model.eval()
    with torch.no_grad():
        features = classifier.model.get_image_features(**inputs)
        features = torch.nn.functional.normalize(features, p=2, dim=-1)
    return tuple(float(value) for value in features[0].tolist())


def get_image_similarity(first_path, second_path):
    if not first_path or not second_path:
        return None
    first = Path(first_path)
    second = Path(second_path)
    if not first.is_file() or not second.is_file():
        return None
    first_embedding = get_image_embedding(str(first), first.stat().st_mtime_ns)
    second_embedding = get_image_embedding(str(second), second.stat().st_mtime_ns)
    if first_embedding is None or second_embedding is None:
        return None
    cosine = sum(a * b for a, b in zip(first_embedding, second_embedding))
    return max(0.0, min(1.0, (cosine + 1.0) / 2.0))


def configured_match_weights():
    keys = ("text", "image", "category", "location", "date")
    weights = {}
    for key in keys:
        value = float(os.getenv(f"MATCH_WEIGHT_{key.upper()}", "0"))
        if value < 0:
            raise ValueError(f"MATCH_WEIGHT_{key.upper()} must not be negative.")
        weights[key] = value
    if not any(weights.values()):
        return None
    return weights


def _safe_user(user):
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "role": user["role"],
    }


def clear_login_state():
    for key in list(st.session_state):
        del st.session_state[key]
    st.rerun()


def check_session():
    principal = st.session_state.get("user")
    if not principal:
        return None
    now = time.time()
    last_activity = st.session_state.get("last_activity", now)
    if now - last_activity > SESSION_IDLE_SECONDS:
        clear_login_state()
        return None
    try:
        user = db.get_authenticated_user(DB_PATH, principal)
    except AuthorizationError:
        clear_login_state()
        return None
    st.session_state["user"] = _safe_user(user)
    st.session_state["last_activity"] = now
    return st.session_state["user"]


def require_admin_reauthentication(user):
    if user["role"] != "admin":
        st.error("Access denied. This page is for administrators.")
        return False
    reauthenticated_at = st.session_state.get("admin_reauthenticated_at")
    if reauthenticated_at and 0 <= time.time() - reauthenticated_at <= 300:
        st.caption("Administrator verification is active for up to five minutes.")
        return True
    with st.form("admin_reauthentication_form"):
        password = st.text_input("Confirm administrator password", type="password")
        submitted = st.form_submit_button("Verify administrator")
    if submitted:
        authenticated = db.authenticate_user(DB_PATH, user["email"], password)
        if authenticated and authenticated["role"] == "admin":
            st.session_state["admin_reauthenticated_at"] = time.time()
            st.rerun()
        st.error("Administrator verification failed.")
    st.info("Re-enter your administrator password to access private records.")
    return False


def render_public_qr_page(token):
    st.title("🔎 Symbiote Lofo AI")
    if not db.lookup_public_qr(DB_PATH, token):
        st.error("This QR code is invalid, inactive, or has been revoked.")
        st.caption("No owner information is available from a QR scan.")
        return
    st.success("This item is registered with the campus lost-and-found system.")
    st.write("If you found it, share where it can be collected. A scan does not prove ownership.")
    with st.form("public_found_item_form", clear_on_submit=True):
        description = st.text_area(
            "Where and when did you find it?",
            max_chars=1000,
        )
        location = st.text_input("Campus location", max_chars=200)
        submitted = st.form_submit_button("Send found-item notice")
    if submitted:
        if not description.strip() or not location.strip():
            st.warning("Enter a short note and campus location.")
        else:
            db.save_public_found_report(
                DB_PATH,
                "Registered item",
                description.strip(),
                location.strip(),
            )
            st.success("Your found-item note was saved for administrator review.")
            st.query_params.clear()
            st.rerun()


def render_login_page():
    st.title("🔐 Symbiote Lofo AI")
    st.caption("Student and administrator access. Date of birth is checked for age and not saved to your account.")
    st.warning(
        "Important: After logging in, go to **My Profile** and generate and securely "
        "save your backup security codes. This is required for self-service password "
        "recovery; codes are shown only once, and users without a code must contact "
        "an administrator for identity-verified help."
    )
    (
        student_login_tab,
        admin_login_tab,
        student_signup_tab,
        admin_signup_tab,
        forgot_password_tab,
    ) = st.tabs(
        ["Student login", "Admin login", "Student signup", "Admin signup", "Forgot password"]
    )
    with student_login_tab:
        with st.form("student_login_form"):
            email = st.text_input("College email")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Student login")
        if submitted:
            if not email.strip() or not password:
                st.warning("Enter your email and password.")
            else:
                user = db.authenticate_user(DB_PATH, email, password)
                if user and user["role"] == "student":
                    st.session_state["user"] = _safe_user(user)
                    st.session_state["last_activity"] = time.time()
                    st.rerun()
                st.error("Invalid student credentials.")
    with admin_login_tab:
        with st.form("admin_login_form"):
            email = st.text_input("Administrator email")
            password = st.text_input("Administrator password", type="password")
            submitted = st.form_submit_button("Admin login")
        if submitted:
            if not email.strip() or not password:
                st.warning("Enter your administrator email and password.")
            else:
                user = db.authenticate_user(DB_PATH, email, password)
                if user and user["role"] == "admin":
                    st.session_state["user"] = _safe_user(user)
                    st.session_state["last_activity"] = time.time()
                    st.rerun()
                st.error("Invalid administrator credentials.")
    with student_signup_tab:
        with st.form("student_signup_form"):
            name = st.text_input("Full name", max_chars=120)
            email = st.text_input("College email", max_chars=254)
            date_of_birth = st.date_input(
                "Date of birth (used only for age verification; not saved)",
                value=None,
                min_value=date(1900, 1, 1),
                max_value=date.today(),
                key="student_signup_dob",
            )
            password = st.text_input("Password", type="password")
            confirmation = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button("Create student account")
        if submitted:
            if not name.strip() or not email.strip() or not password or not date_of_birth:
                st.warning("Complete all required fields.")
            elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
                st.warning("Enter a valid email address.")
            elif not is_under_age(date_of_birth, 23):
                st.error("You must be under 23 years old to create a student account.")
            elif len(password) < 12:
                st.warning("Use a password with at least 12 characters.")
            elif password != confirmation:
                st.warning("Passwords do not match.")
            else:
                try:
                    user = db.create_student(
                        DB_PATH,
                        name,
                        email,
                        hash_password(password),
                    )
                except Exception as error:
                    if isinstance(error, (ValueError, db.sqlite3.IntegrityError)):
                        st.error("An account with that email may already exist.")
                    else:
                        raise
                else:
                    st.session_state["user"] = _safe_user(user)
                    st.session_state["last_activity"] = time.time()
                    st.success("Student account created.")
                    st.rerun()
    with admin_signup_tab:
        st.caption(
            "Anyone may apply using any valid email address. The uploaded image is "
            "checked locally for matching name and date-of-birth text."
        )
        with st.form("admin_signup_form"):
            name = st.text_input("Administrator name", max_chars=120)
            email = st.text_input("Administrator email", max_chars=254)
            date_of_birth = st.date_input(
                "Date of birth (used only for age verification; not saved)",
                value=None,
                min_value=date(1900, 1, 1),
                max_value=date.today(),
                key="admin_signup_dob",
            )
            document_photo = st.file_uploader(
                "Aadhaar photo for local name and DOB text matching",
                type=["jpg", "jpeg", "png", "webp"],
                help=(
                    "The photo is processed by local OCR in memory. It is not saved "
                    "to disk or sent to an external OCR service."
                ),
                key="admin_signup_aadhaar_photo",
            )
            st.caption(
                "OCR only checks whether printed text matches your entries. It cannot "
                "authenticate Aadhaar or prove the document is genuine."
            )
            password = st.text_input("Password", type="password")
            confirmation = st.text_input("Confirm password", type="password")
            submitted = st.form_submit_button(
                "Create administrator account",
            )
        if submitted:
            if (
                not name.strip()
                or not email.strip()
                or not password
                or not date_of_birth
                or not document_photo
            ):
                st.warning("Complete all required fields.")
            elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
                st.warning("Enter a valid email address.")
            elif len(password) < 12:
                st.warning("Use a password with at least 12 characters.")
            elif password != confirmation:
                st.warning("Passwords do not match.")
            else:
                try:
                    identity_check = check_identity_document(
                        document_photo.getvalue(),
                        name,
                        date_of_birth,
                        command=os.getenv("TESSERACT_CMD", "tesseract"),
                    )
                except (IdentityOCRUnavailable, ValueError) as error:
                    st.error(str(error))
                else:
                    if not identity_check["name_matches"]:
                        st.error(
                            "Local OCR could not match the entered name to the document."
                        )
                    elif not identity_check["date_of_birth_matches"]:
                        st.error(
                            "Local OCR could not match the entered date of birth to the document."
                        )
                    elif not identity_check["meets_minimum_age"]:
                        st.error(
                            "The document date of birth must show that you are at least 23."
                        )
                    else:
                        try:
                            user = db.create_admin(
                                DB_PATH,
                                name,
                                email,
                                hash_password(password),
                            )
                        except (ValueError, db.sqlite3.IntegrityError):
                            st.error("An account with that email may already exist.")
                        else:
                            st.session_state["user"] = _safe_user(user)
                            st.session_state["last_activity"] = time.time()
                            st.success("Administrator account created.")
                            st.rerun()
    with forgot_password_tab:
        st.subheader("Reset your password")
        st.caption(
            "Use a one-time backup security code generated in My Profile. If you no "
            "longer have a code, contact an administrator for identity-verified help."
        )
        with st.form("password_reset_form", clear_on_submit=True):
            reset_email = st.text_input("Account email", max_chars=254, key="reset_account_email")
            credential = st.text_input(
                "Backup security code",
                max_chars=64,
            )
            new_password = st.text_input("New password", type="password")
            confirm_password = st.text_input("Confirm new password", type="password")
            reset_submitted = st.form_submit_button("Reset password")
        if reset_submitted:
            if not reset_email.strip() or not credential:
                st.warning("Enter your account email and verification credential.")
            elif len(new_password) < 12:
                st.warning("Use a password with at least 12 characters.")
            elif new_password != confirm_password:
                st.warning("Passwords do not match.")
            elif db.reset_password(
                DB_PATH,
                reset_email,
                credential.strip(),
                hash_password(new_password),
                method="recovery",
            ):
                st.success("Password reset. You can now sign in with your new password.")
            else:
                st.error(
                    "Password reset failed. Check your security code and try again."
                )


def render_profile_page(user):
    st.title("👤 My profile")
    profile = db.get_student_profile(DB_PATH, user)
    st.write(f"**Name:** {profile['name']}")
    st.write(f"**College email:** {profile['email']}")
    st.write(f"**Department / branch:** {profile['department'] or 'Not set'}")
    st.write(f"**Year of study:** {profile['year_of_study'] or 'Not set'}")
    st.write(f"**Phone:** {profile['phone'] or 'Not set'}")
    st.info(
        "Roll numbers are private. You may enter one below, but it is not shown "
        "on your profile or student report pages; only verified administrators can search it."
    )
    roll_pattern = os.getenv("ROLL_NUMBER_REGEX")
    if roll_pattern:
        st.caption("Your college's configured roll-number validation rule will be applied.")
    else:
        st.caption("No college-specific roll-number pattern is configured.")
    with st.form("profile_update_form"):
        st.text_input("Roll number (optional)", key="profile_roll_input")
        department = st.text_input("Department or branch", value=profile["department"] or "")
        year = st.text_input("Year of study", value=profile["year_of_study"] or "")
        phone = st.text_input("Phone number (optional)", value=profile["phone"] or "")
        submitted = st.form_submit_button("Save profile")
    if submitted:
        try:
            db.update_student_profile(
                DB_PATH,
                user,
                roll_number=st.session_state.get("profile_roll_input", ""),
                department=department,
                year_of_study=year,
                phone=phone,
            )
        except ValueError as error:
            st.error(str(error))
        else:
            st.session_state.pop("profile_roll_input", None)
            st.success("Profile saved. Your roll number remains private.")
            st.rerun()

    st.subheader("Account recovery")
    st.write(
        f"Unused backup security codes: **{db.count_recovery_codes(DB_PATH, user)}**"
    )
    st.caption(
        "Generate new backup security codes and store them somewhere private. Each code works "
        "once; generating a new set invalidates all previous codes."
    )
    with st.form("recovery_code_generation_form", clear_on_submit=True):
        current_password = st.text_input(
            "Confirm your password to generate codes",
            type="password",
        )
        generate_submitted = st.form_submit_button("Generate backup security codes")
    if generate_submitted:
        authenticated = db.authenticate_user(DB_PATH, user["email"], current_password)
        if not authenticated:
            st.error("Password confirmation failed.")
        else:
            recovery_codes = create_recovery_codes()
            db.replace_recovery_codes(
                DB_PATH,
                user,
                [hash_password(code) for code in recovery_codes],
            )
            st.session_state["new_recovery_codes"] = recovery_codes
            st.rerun()
    if st.session_state.get("new_recovery_codes"):
        st.warning(
            "These codes are shown only in this signed-in session. Save them now; "
            "they cannot be retrieved later."
        )
        st.code("\n".join(st.session_state["new_recovery_codes"]))
        if st.button("I have saved these codes", key="dismiss_recovery_codes"):
            st.session_state.pop("new_recovery_codes", None)
            st.rerun()


def render_dashboard(user):
    reports = db.list_reports(DB_PATH, user, own_only=True)
    total = len(reports)
    lost = sum(1 for item in reports if item["status"] == "Lost")
    found = sum(1 for item in reports if item["status"] == "Found")
    completed = sum(1 for item in reports if item["is_completed"])
    st.title("📊 Dashboard")
    st.caption(f"Welcome, {user['name']}. These totals are for your reports.")
    columns = st.columns(4)
    columns[0].metric("My reports", total)
    columns[1].metric("Lost", lost)
    columns[2].metric("Found", found)
    columns[3].metric("Completed", completed)
    if reports:
        st.subheader("Your recent reports")
        for report in reports[:5]:
            with st.container(border=True):
                st.markdown(f"### {report['item_name']}")
                st.write(f"**Direction:** {report['status']}")
                st.write(f"**Workflow:** {report['workflow_status']}")
                st.caption(f"Reported: {report['created_at']}")
    else:
        st.info("No reports yet. Start by reporting a lost or found item.")


def _identify_report(description, photo_bytes, direction, location):
    import io

    image = Image.open(io.BytesIO(photo_bytes)).convert("RGB")
    results = load_model()(image, candidate_labels=list(ITEMS.keys()))
    image_guess = results[0]["label"]
    text_guess = identify_from_text(description)
    st.session_state["suggested_item"] = text_guess or image_guess
    st.session_state["image_guess"] = image_guess
    st.session_state["text_guess"] = text_guess
    st.session_state["report_photo_bytes"] = photo_bytes
    st.session_state["report_direction"] = direction
    st.session_state["report_description"] = description
    st.session_state["report_location"] = location


def render_report_page(user):
    st.title("🧾 Report a lost or found item")
    direction_label = st.radio(
        "Report direction",
        ["Lost", "Found"],
        horizontal=True,
        key="report_direction_input",
    )
    description = st.text_area(
        "Item description",
        max_chars=1500,
        placeholder="Describe its appearance, brand, colour, marks, and where it was lost or found.",
    )
    uploaded = st.file_uploader(
        "Item photo (required for AI identification)",
        type=["jpg", "jpeg", "png", "webp"],
        key="report_photo",
    )
    if uploaded:
        st.image(uploaded, caption="Selected report photo", width=280)
    location = st.text_input("Campus location", max_chars=200)

    if st.button("Check for duplicates and identify", type="primary"):
        if not description.strip():
            st.error("Enter a description before continuing.")
        elif uploaded is None:
            st.error("Upload an item photo to use AI identification.")
        elif not location.strip():
            st.error("Enter the campus location.")
        else:
            photo_bytes = uploaded.getvalue()
            if len(photo_bytes) > int(os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024))):
                st.error("Photo exceeds the configured upload-size limit.")
            else:
                window_hours = max(1, int(os.getenv("DUPLICATE_WINDOW_HOURS", "72")))
                cutoff = (datetime.now() - timedelta(hours=window_hours)).isoformat(timespec="seconds")
                duplicates = db.find_duplicate_reports(
                    DB_PATH,
                    user,
                    direction_label,
                    identify_from_text(description) or "",
                    "",
                    description,
                    location,
                    cutoff,
                )
                st.session_state["potential_duplicates"] = duplicates
                st.session_state["pending_report_input"] = {
                    "description": description,
                    "photo_bytes": photo_bytes,
                    "direction": direction_label,
                    "location": location,
                }
                if duplicates:
                    st.warning(
                        "Some of your own recent reports may be duplicates. "
                        "Review them before deciding whether to continue."
                    )
                else:
                    try:
                        _identify_report(description, photo_bytes, direction_label, location)
                    except (ValueError, OSError) as error:
                        st.error(f"Could not identify that image: {error}")

    duplicates = st.session_state.get("potential_duplicates", [])
    pending = st.session_state.get("pending_report_input")
    if duplicates and pending:
        for report in duplicates:
            with st.container(border=True):
                st.write(f"**Your earlier report:** {report['item_name']} — {report['status']}")
                st.write(f"**Description:** {report['description'] or 'Not provided'}")
                st.write(f"**Location:** {report['location'] or 'Not provided'}")
                st.caption(f"Submitted: {report['created_at']}")
        with st.form("duplicate_confirmation_form"):
            confirm = st.checkbox("I reviewed my earlier report and want to submit another.")
            continue_clicked = st.form_submit_button("Continue to AI identification")
        if continue_clicked:
            if not confirm:
                st.warning("Confirm after reviewing your own potential duplicates.")
            else:
                try:
                    _identify_report(
                        pending["description"],
                        pending["photo_bytes"],
                        pending["direction"],
                        pending["location"],
                    )
                    st.session_state.pop("potential_duplicates", None)
                    st.session_state.pop("pending_report_input", None)
                except (ValueError, OSError) as error:
                    st.error(f"Could not identify that image: {error}")

    if "suggested_item" in st.session_state:
        st.subheader("AI suggestions")
        st.write(f"**Image prediction:** {st.session_state['image_guess']}")
        if st.session_state.get("text_guess"):
            st.write(f"**Description keyword suggestion:** {st.session_state['text_guess']}")
        with st.form("confirm_report_form"):
            choices = list(ITEMS)
            item_name = st.selectbox(
                "Confirm item name",
                choices,
                index=choices.index(st.session_state["suggested_item"]),
            )
            category = st.selectbox(
                "Confirm category",
                CATEGORIES,
                index=CATEGORIES.index(ITEMS[item_name]),
            )
            save_clicked = st.form_submit_button("Save report")
        if save_clicked:
            class UploadedBytes:
                def getvalue(self):
                    return st.session_state["report_photo_bytes"]

            image_path = None
            try:
                image_path = save_uploaded_image(UploadedBytes(), UPLOAD_DIR)
                report_id = db.save_report(
                    DB_PATH,
                    user,
                    st.session_state["report_direction"],
                    item_name,
                    category,
                    st.session_state["report_description"],
                    st.session_state["report_location"],
                    image_path,
                )
            except Exception:
                if image_path:
                    Path(image_path).unlink(missing_ok=True)
                raise
            notification_errors = send_report_notifications(report_id, item_name, user)
            for key in (
                "suggested_item",
                "image_guess",
                "text_guess",
                "report_photo_bytes",
                "report_direction",
                "report_description",
                "report_location",
                "potential_duplicates",
                "pending_report_input",
            ):
                st.session_state.pop(key, None)
            st.success("Your report was saved.")
            for error in notification_errors:
                st.warning(f"Report saved, but an email notification failed: {error}")
            st.rerun()


def send_report_notifications(report_id, item_name, user):
    import smtplib
    from email.message import EmailMessage

    host = os.getenv("SMTP_HOST")
    if not host:
        return []
    recipients = [user["email"]]
    recipients.extend(
        address.strip()
        for address in os.getenv("ADMIN_EMAILS", "").split(",")
        if address.strip()
    )
    subject = "Symbiote Lofo AI report received"
    sender = os.getenv("SMTP_FROM_EMAIL", os.getenv("SMTP_USERNAME", ""))
    errors = []
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as server:
            if os.getenv("SMTP_USE_TLS", "true").lower() == "true":
                server.starttls()
            username = os.getenv("SMTP_USERNAME")
            password = os.getenv("SMTP_PASSWORD")
            if username and password:
                server.login(username, password)
            for recipient in recipients:
                message = EmailMessage()
                message["Subject"] = subject
                message["From"] = sender
                message["To"] = recipient
                message.set_content(
                    f"Your {item_name} report (reference {report_id}) was received. "
                    "Sign in to view its status."
                )
                try:
                    server.send_message(message, to_addrs=[recipient])
                except (OSError, smtplib.SMTPException) as error:
                    db.log_email(
                        DB_PATH,
                        report_id,
                        recipient,
                        subject,
                        "failed",
                    )
                    errors.append(type(error).__name__)
                else:
                    db.log_email(
                        DB_PATH,
                        report_id,
                        recipient,
                        subject,
                        "sent",
                    )
    except (OSError, smtplib.SMTPException) as error:
        for recipient in recipients:
            db.log_email(DB_PATH, report_id, recipient, subject, "failed")
        return [type(error).__name__]
    return errors


def render_reports_page(user, own_only=False):
    st.title("📋 My reports" if own_only else "📋 Campus reports")
    reports = db.list_reports(DB_PATH, user, own_only=own_only)
    if not reports:
        st.info("You have not submitted any reports yet." if own_only else "No reports have been submitted yet.")
        return
    frame = pd.DataFrame(reports)
    status_filter = st.radio("Direction", ["All", "Lost", "Found"], horizontal=True)
    resolution_filter = st.radio(
        "Workflow",
        ["All"] + ALLOWED_STATUS,
        horizontal=True,
    )
    categories = sorted(frame["category"].dropna().unique().tolist())
    category_filter = st.selectbox("Category", ["All categories"] + categories)
    search = st.text_input("Search item, description, category, or location")
    if status_filter != "All":
        frame = frame[frame["status"] == status_filter]
    if resolution_filter != "All":
        frame = frame[frame["workflow_status"] == resolution_filter]
    if category_filter != "All categories":
        frame = frame[frame["category"] == category_filter]
    if search.strip():
        fields = ["item_name", "category", "description", "location"]
        mask = frame[fields].fillna("").apply(
            lambda column: column.str.contains(search.strip(), case=False, regex=False)
        ).any(axis=1)
        frame = frame[mask]
    st.subheader(f"Reports: {len(frame)}")
    for _, row in frame.iterrows():
        with st.container(border=True):
            st.markdown(f"### {row['item_name']}")
            st.write(f"**Direction:** {row['status']}")
            st.write(f"**Workflow:** {row['workflow_status']}")
            st.write(f"**Category:** {row['category']}")
            st.write(f"**Description:** {row['description'] or 'Not provided'}")
            st.write(f"**Location:** {row['location'] or 'Not specified'}")
            st.caption(f"Reported: {row['created_at']}")
            if row["is_completed"]:
                st.success("✅ Completed")
            else:
                can_complete = own_only and bool(row.get("is_owner", True))
                if can_complete and st.button(
                    "Mark my report as done",
                    key=f"complete_{row['id']}",
                ):
                    if db.mark_report_completed(DB_PATH, user, int(row["id"])):
                        st.success("Your report is now marked done.")
                        st.rerun()
            if own_only:
                history = db.get_status_history(DB_PATH, user, int(row["id"]))
                if history:
                    with st.expander("Status history"):
                        for entry in history:
                            st.caption(
                                f"{entry['changed_at']}: "
                                f"{entry['old_status'] or 'New'} → {entry['new_status']}"
                            )


def render_registered_items(user):
    st.title("🔐 My registered items")
    st.caption("Ownership details are private to you and authorized administrators.")
    with st.form("registered_item_form", clear_on_submit=True):
        name = st.text_input("Item name", max_chars=120)
        category = st.selectbox("Category", CATEGORIES)
        details = st.text_area("Detailed description", max_chars=1500)
        brand = st.text_input("Brand and model", max_chars=200)
        color = st.text_input("Colour", max_chars=120)
        marks = st.text_area("Identifying marks or stickers", max_chars=1000)
        serial = st.text_input("Serial number (optional)", max_chars=200)
        photo = st.file_uploader(
            "Optional private item photo",
            type=["jpg", "jpeg", "png", "webp"],
            key="registered_item_photo",
        )
        submitted = st.form_submit_button("Register item and create QR")
    if submitted:
        if not name.strip() or not details.strip():
            st.warning("Enter the item name and detailed description.")
        elif not os.getenv("APP_BASE_URL"):
            st.error("Set APP_BASE_URL before creating QR codes.")
        else:
            image_path = None
            try:
                token = create_qr_token()
                payload = build_qr_payload(os.getenv("APP_BASE_URL"), token)
                qr_png = make_qr_png(payload)
                if photo:
                    image_path = save_uploaded_image(photo, UPLOAD_DIR)
                item_id = db.create_registered_item(
                    DB_PATH,
                    user,
                    item_name=name,
                    category=category,
                    detailed_description=details,
                    brand_model=brand,
                    color=color,
                    identifying_marks=marks,
                    serial_number=serial,
                    photo_path=image_path,
                    qr_token_hash=hash_qr_token(token),
                )
            except (ImportError, ValueError, OSError) as error:
                if image_path:
                    Path(image_path).unlink(missing_ok=True)
                st.error(str(error))
            else:
                st.session_state["new_item_qr"] = {
                    "item_id": item_id,
                    "png": qr_png,
                }
                st.success("Private item registered. The QR code contains no personal details.")
                st.rerun()

    pending_qr = st.session_state.get("new_item_qr")
    if pending_qr:
        st.subheader(f"QR softcopy for item {pending_qr['item_id']}")
        st.image(pending_qr["png"], width=220)
        st.download_button(
            "Download QR as PNG",
            pending_qr["png"],
            file_name=f"registered-item-{pending_qr['item_id']}.png",
            mime="image/png",
            key=f"download_new_qr_{pending_qr['item_id']}",
        )
        if st.button("Hide this QR preview"):
            st.session_state.pop("new_item_qr", None)
            st.rerun()

    items = db.list_registered_items(DB_PATH, user)
    if not items:
        st.info("No private items registered yet.")
        return
    for item in items:
        with st.container(border=True):
            st.markdown(f"### {item['item_name']}")
            st.write(f"**Category:** {item['category']}")
            st.write(f"**Description:** {item['detailed_description']}")
            st.write(f"**Brand / model:** {item['brand_model'] or 'Not provided'}")
            st.write(f"**Colour:** {item['color'] or 'Not provided'}")
            st.write(f"**Identifying marks:** {item['identifying_marks'] or 'Not provided'}")
            st.write(f"**Serial number:** {item['serial_number'] or 'Not provided'}")
            st.write(f"**Created:** {item['created_at']}")
            if item["photo_path"] and Path(item["photo_path"]).is_file():
                st.image(item["photo_path"], width=240)
            if item["is_active"]:
                st.caption("The QR token is stored only as a hash; creating a new code revokes the old one.")
                if st.button("Create / rotate QR softcopy", key=f"rotate_qr_{item['id']}"):
                    try:
                        token = create_qr_token()
                        payload = build_qr_payload(os.getenv("APP_BASE_URL"), token)
                        qr_png = make_qr_png(payload)
                        db.rotate_registered_item_qr(DB_PATH, user, item["id"], token)
                        st.session_state["new_item_qr"] = {
                            "item_id": item["id"],
                            "png": qr_png,
                        }
                        st.rerun()
                    except (ImportError, ValueError, OSError) as error:
                        st.error(str(error))
                if st.button("Deactivate item", key=f"deactivate_item_{item['id']}"):
                    db.deactivate_registered_item(DB_PATH, user, item["id"])
                    st.success("Item deactivated; its QR code is revoked.")
                    st.rerun()
            else:
                st.warning("Inactive; the QR code is revoked.")


def render_claims_page(user):
    st.title("📝 Claims")
    found_reports = [
        report for report in db.list_reports(DB_PATH, user)
        if report["status"] == "Found"
        and not report["is_completed"]
        and report["workflow_status"] not in {"Returned", "Closed"}
    ]
    my_lost_reports = [
        report for report in db.list_reports(DB_PATH, user, own_only=True)
        if report["status"] == "Lost"
    ]
    if found_reports:
        labels = {
            f"{report['id']} · {report['item_name']} · {report['location'] or 'location not specified'}": report["id"]
            for report in found_reports
        }
        with st.form("submit_claim_form"):
            found_label = st.selectbox("Found report", list(labels))
            lost_labels = {"No linked Lost report": None}
            lost_labels.update({
                f"{report['id']} · {report['item_name']}": report["id"]
                for report in my_lost_reports
            })
            lost_label = st.selectbox("Link one of your Lost reports (optional)", list(lost_labels))
            evidence = st.text_area(
                "Private ownership evidence (only you and admins can read this)",
                max_chars=2000,
            )
            submitted = st.form_submit_button("Submit claim")
        if submitted:
            try:
                claim_id = db.create_claim(
                    DB_PATH,
                    user,
                    labels[found_label],
                    evidence,
                    lost_labels[lost_label],
                )
            except (ValueError, AuthorizationError) as error:
                st.error(str(error))
            else:
                st.success(f"Claim {claim_id} submitted for administrator review.")
                st.rerun()
    else:
        st.info("There are no open Found reports to claim.")

    st.subheader("Your claims")
    claims = db.list_my_claims(DB_PATH, user)
    if not claims:
        st.info("You have not submitted any claims.")
    for claim in claims:
        with st.container(border=True):
            st.markdown(f"### Claim {claim['id']} · {claim['item_name']}")
            st.write(f"**Status:** {claim['status']}")
            st.write(f"**Your private evidence:** {claim['ownership_evidence']}")
            st.caption(f"Submitted: {claim['submitted_at']}")
            if claim["reviewed_at"]:
                st.caption(f"Reviewed: {claim['reviewed_at']}")
                st.write(f"**Decision note:** {claim['review_reason'] or 'None'}")
            if claim["status"] == "Pending" and st.button(
                "Withdraw claim",
                key=f"withdraw_claim_{claim['id']}",
            ):
                db.withdraw_claim(DB_PATH, user, claim["id"])
                st.rerun()


def render_matching_page(user):
    st.title("🤝 Possible Lost ↔ Found matches")
    st.warning(
        "Similarity is a heuristic for review only. It is not proof of ownership "
        "and never approves a claim."
    )
    reports = db.list_reports(DB_PATH, user)
    if st.button("Find possible matches", type="primary"):
        paths = {row["id"]: row.get("image_path") for row in reports}
        image_scores = {}
        lost = [row for row in reports if row["status"] == "Lost" and row["image_path"]]
        found = [row for row in reports if row["status"] == "Found" and row["image_path"]]
        weights = configured_match_weights()
        with st.spinner("Comparing report text, dates, locations, and available photos..."):
            for lost_report in lost:
                for found_report in found:
                    score = get_image_similarity(
                        lost_report["image_path"],
                        found_report["image_path"],
                    )
                    if score is not None:
                        image_scores[(lost_report["id"], found_report["id"])] = score
            matches = rank_lost_found_matches(reports, image_scores, weights)
        st.session_state["ranked_matches"] = matches
    matches = st.session_state.get("ranked_matches", [])
    if not matches:
        st.info("No possible Lost/Found pairs are available yet.")
        return
    for match in matches:
        lost = match["lost_report"]
        found = match["found_report"]
        with st.container(border=True):
            st.markdown(f"### {match['score'] * 100:.0f}% heuristic similarity")
            left, right = st.columns(2)
            left.write(f"**Lost:** {lost['item_name']} · {lost['category']}")
            left.write(f"{lost['description'] or 'No description'}")
            left.write(f"Location: {lost['location'] or 'Unknown'}")
            right.write(f"**Found:** {found['item_name']} · {found['category']}")
            right.write(f"{found['description'] or 'No description'}")
            right.write(f"Location: {found['location'] or 'Unknown'}")
            explanations = match["explanations"]
            st.write("**Possible reasons:** " + ("; ".join(explanations) if explanations else "Limited matching information"))
            st.caption("Please submit a claim for admin verification; do not rely on the score as ownership evidence.")


def render_admin_page(user):
    st.title("🛡️ Administrator tools")
    if not require_admin_reauthentication(user):
        return
    reauth_at = st.session_state.get("admin_reauthenticated_at")
    tabs = st.tabs(
        [
            "Overview and statuses",
            "Roll-number search",
            "Registered items",
            "Claim review and handovers",
            "QR lookup",
            "Audit log",
        ]
    )

    with tabs[0]:
        reports = db.list_reports(
            DB_PATH,
            user,
            admin=True,
            reauthenticated_at=reauth_at,
        )
        if reports:
            frame = pd.DataFrame(reports)
            columns = [
                "id", "status", "workflow_status", "is_completed",
                "item_name", "category", "location", "reporter_name", "created_at",
            ]
            st.dataframe(frame[columns], use_container_width=True)
            totals = st.columns(3)
            totals[0].metric("Reports", len(frame))
            totals[1].metric("Open", int((frame["workflow_status"] == "Open").sum()))
            totals[2].metric("Completed", int(frame["is_completed"].sum()))
            choices = [status for status in ALLOWED_STATUS if status not in {"Returned", "Approved for Handover"}]
            for report in reports:
                with st.expander(f"Report {report['id']}: {report['item_name']} — {report['workflow_status']}"):
                    next_status = st.selectbox(
                        "New workflow status",
                        choices,
                        index=choices.index(report["workflow_status"])
                        if report["workflow_status"] in choices else 0,
                        key=f"status_{report['id']}",
                    )
                    note = st.text_input("Admin-only review note", key=f"status_note_{report['id']}")
                    if st.button("Update status", key=f"save_status_{report['id']}"):
                        try:
                            db.update_workflow_status(DB_PATH, user, report["id"], next_status, note)
                        except (ValueError, AuthorizationError) as error:
                            st.error(str(error))
                        else:
                            st.success("Workflow status updated.")
                            st.rerun()
                    for history in db.get_status_history(
                        DB_PATH, user, report["id"], admin=True, reauthenticated_at=reauth_at
                    ):
                        st.caption(
                            f"{history['changed_at']}: {history['old_status'] or 'New'} → "
                            f"{history['new_status']} · {history.get('admin_note') or 'No private note'}"
                        )
        else:
            st.info("No reports yet.")

    with tabs[1]:
        st.subheader("Private student lookup")
        st.caption("Roll numbers are exact strings; matching preserves leading zeroes.")
        with st.form("admin_roll_search_form"):
            roll_number = st.text_input("Roll number")
            submitted = st.form_submit_button("Search")
        if submitted:
            try:
                results = db.admin_search_students_by_roll(
                    DB_PATH, user, roll_number, reauth_at
                )
            except AuthorizationError as error:
                st.error(str(error))
            else:
                if not results:
                    st.info("No matching student found.")
                for profile in results:
                    st.write(f"**Name:** {profile['name']}")
                    st.write(f"**Roll number:** {profile['roll_number']}")
                    st.write(f"**Email:** {profile['email']}")
                    st.write(f"**Department / branch:** {profile['department'] or 'Not set'}")
                    st.write(f"**Year of study:** {profile['year_of_study'] or 'Not set'}")
                    st.write(f"**Phone:** {profile['phone'] or 'Not set'}")

    with tabs[2]:
        items = db.list_registered_items(
            DB_PATH,
            user,
            reauthenticated_at=reauth_at,
        )
        if not items:
            st.info("No registered items.")
        for item in items:
            with st.expander(f"Item {item['id']}: {item['item_name']}"):
                st.write(f"Owner account: {item['owner_id']}")
                st.write(f"Category: {item['category']}")
                st.write(f"Description: {item['detailed_description']}")
                st.write(f"Brand / model: {item['brand_model'] or 'Not provided'}")
                st.write(f"Colour: {item['color'] or 'Not provided'}")
                st.write(f"Identifying marks: {item['identifying_marks'] or 'Not provided'}")
                st.write(f"Serial number: {item['serial_number'] or 'Not provided'}")

    with tabs[3]:
        claims = db.list_admin_claims(DB_PATH, user, reauth_at)
        if not claims:
            st.info("No claims have been submitted.")
        for claim in claims:
            with st.expander(
                f"Claim {claim['id']} · {claim['item_name']} · {claim['status']}"
            ):
                st.write(f"Found report: {claim['found_report_id']}")
                st.write(f"Claimant: {claim['claimant_name']} ({claim['claimant_email']})")
                st.write(f"**Private ownership evidence:** {claim['ownership_evidence']}")
                st.caption(f"Submitted: {claim['submitted_at']}")
                if claim["status"] == "Pending":
                    reason = st.text_area("Decision reason", key=f"claim_reason_{claim['id']}")
                    one, two = st.columns(2)
                    if one.button("Approve for handover", key=f"approve_{claim['id']}"):
                        try:
                            db.review_claim(DB_PATH, user, claim["id"], "Approved", reason, reauth_at)
                        except (ValueError, AuthorizationError, db.sqlite3.IntegrityError) as error:
                            st.error(str(error))
                        else:
                            st.success("Claim approved; complete the handover after verifying identity.")
                            st.rerun()
                    if two.button("Reject claim", key=f"reject_{claim['id']}"):
                        try:
                            db.review_claim(DB_PATH, user, claim["id"], "Rejected", reason, reauth_at)
                        except (ValueError, AuthorizationError) as error:
                            st.error(str(error))
                        else:
                            st.success("Claim rejected with a recorded reason.")
                            st.rerun()
                elif claim["status"] == "Approved":
                    notes = st.text_input("Handover note", key=f"handover_note_{claim['id']}")
                    if st.button("Complete verified handover", key=f"handover_{claim['id']}"):
                        try:
                            db.complete_handover(DB_PATH, user, claim["id"], notes, reauth_at)
                        except (ValueError, AuthorizationError, db.sqlite3.IntegrityError) as error:
                            st.error(f"Handover was not completed: {error}")
                        else:
                            st.success("Handover recorded; other pending claims were closed.")
                            st.rerun()

    with tabs[4]:
        with st.form("admin_qr_lookup"):
            token = st.text_input("QR token (private administrator lookup)")
            submitted = st.form_submit_button("Look up registered owner")
        if submitted:
            try:
                item = db.admin_lookup_qr(DB_PATH, user, token, reauth_at)
            except AuthorizationError as error:
                st.error(str(error))
            else:
                if not item:
                    st.info("No active registration matched this token.")
                else:
                    st.write(f"**Item:** {item['item_name']}")
                    st.write(f"**Owner account:** {item['owner_id']}")
                    st.write(f"**Owner name:** {item['owner_name']}")
                    st.write(f"**Owner email:** {item['owner_email']}")
                    st.write(f"**Owner roll number:** {item['owner_roll_number'] or 'Not provided'}")
                    st.write(f"**Owner department:** {item['owner_department'] or 'Not provided'}")
                    st.write(f"**Owner year:** {item['owner_year_of_study'] or 'Not provided'}")
                    st.write(f"**Owner phone:** {item['owner_phone'] or 'Not provided'}")
                    st.write(f"**Description:** {item['detailed_description']}")
                    st.write(f"**Serial number:** {item['serial_number'] or 'Not provided'}")

    with tabs[5]:
        logs = db.list_audit_log(DB_PATH, user, reauth_at)
        st.dataframe(pd.DataFrame(logs), use_container_width=True)


def main():
    apply_theme()
    prepare_database(str(DB_PATH), str(DATA_DIR))
    bootstrap_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "")
    bootstrap_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    if (
        (bootstrap_email or bootstrap_password)
        and not st.session_state.get("_admin_bootstrap_checked")
    ):
        db.bootstrap_admin(DB_PATH, bootstrap_email, bootstrap_password)
        st.session_state["_admin_bootstrap_checked"] = True
    qr_token = st.query_params.get("qr")
    if qr_token:
        render_public_qr_page(qr_token)
        return
    user = check_session()
    if not user:
        render_login_page()
        return

    st.sidebar.title("Symbiote Lofo AI")
    st.sidebar.write(f"👤 {user['name']}")
    st.sidebar.caption(user["email"])
    pages = [
        "Dashboard",
        "Report Item",
        "My Reports",
        "Campus Reports",
        "Claims",
        "Possible Matches",
        "My Registered Items",
        "My Profile",
    ]
    if user["role"] == "admin":
        pages.append("Admin")
    selected = st.sidebar.radio("Navigation", pages)
    if st.sidebar.button("Logout"):
        clear_login_state()

    routes = {
        "Dashboard": lambda: render_dashboard(user),
        "Report Item": lambda: render_report_page(user),
        "My Reports": lambda: render_reports_page(user, own_only=True),
        "Campus Reports": lambda: render_reports_page(user),
        "Claims": lambda: render_claims_page(user),
        "Possible Matches": lambda: render_matching_page(user),
        "My Registered Items": lambda: render_registered_items(user),
        "My Profile": lambda: render_profile_page(user),
        "Admin": lambda: render_admin_page(user),
    }
    routes[selected]()


if __name__ == "__main__":
    main()
