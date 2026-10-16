# Symbiote Lofo AI

A Streamlit app for college lost-and-found reports with CLIP image suggestions, SQLite storage, account sign-in, an admin dashboard, report completion controls, and optional email notifications. The interface uses a crimson-red and green color theme.

## Run locally

Use Python 3.12. From this directory:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

Open the local URL printed by Streamlit. The first image identification downloads the CLIP model and can take a few minutes. The database and uploaded photos are stored in this directory by default.

## Deploy this standalone repository to Render with Docker

1. Push this repository to GitHub. In Render, choose **New + → Web Service** and connect the repository.
2. Select **Docker** as the runtime. Leave **Root Directory** blank so Render uses the repository root and its `Dockerfile`. If deploying from the original Replit-Clone repository instead, set **Root Directory** to `lost_found_app`.
3. Add a persistent disk mounted at `/var/data`. SQLite data, photos, and the downloaded model cache are stored there. A persistent disk requires a paid Render service; without one, the files can be lost when the service restarts or redeploys.
4. Add these environment variables in the Render service settings:

   | Variable | Required | Purpose |
   | --- | --- | --- |
   | `BOOTSTRAP_ADMIN_EMAIL` | Yes | Email address for the initial administrator |
   | `BOOTSTRAP_ADMIN_PASSWORD` | Yes | Password for the initial administrator, used when creating that account |
   | `ADMIN_EMAILS` | No | Comma-separated recipients for new-report notifications |
   | `SMTP_HOST` | No | SMTP server host for report notifications |
   | `SMTP_PORT` | No | SMTP port; defaults to `587` |
   | `SMTP_USERNAME` | No | SMTP login |
   | `SMTP_PASSWORD` | No | SMTP password or provider app password |
   | `SMTP_FROM_EMAIL` | No | Sender address; defaults to `SMTP_USERNAME` |
   | `SMTP_USE_TLS` | No | Defaults to `true` |
   | `APP_DATA_DIR` | No | Defaults to `/var/data` in Docker |
   | `HF_HOME` | No | Defaults to `/var/data/huggingface` in Docker |

   Set secrets through Render's environment settings, not in source control. The `PORT` variable is supplied by Render and is used by the Docker command.

5. Deploy. On the first startup the administrator account is created from the bootstrap variables. If the account already exists, its current password must match `BOOTSTRAP_ADMIN_PASSWORD` before it can be promoted. Additional administrator accounts can be created through admin signup with any valid email address after the local name/DOB OCR checks pass. Set `APP_BASE_URL` to the deployed HTTPS URL to enable QR creation.
6. Open the public URL shown on the Render service page and test sign-in, a report submission, the **My Reports** page, and the **Mark my report as done** action. Users can complete their own reports; admins can complete any report. Completion is visible and can be filtered in Saved Reports.

For persistent SQLite storage, run only one service instance. This app is not configured for multiple replicas or concurrent shared-disk database access. Keep the admin password and SMTP credentials private, and rotate them in the provider if they are exposed.

## Email notifications and password recovery

Report notifications require `SMTP_HOST` and a sender address (`SMTP_FROM_EMAIL` or `SMTP_USERNAME`). Password resets use only one-time backup security codes generated in My Profile. Users who lose their codes must contact an administrator, who should verify identity using the institution's approved process. Set `ADMIN_EMAILS` to the campus staff recipients.

## Data and accounts

Set `APP_DATA_DIR` to a writable persistent directory to keep the SQLite database and photos across deployments. New passwords are stored using PBKDF2; existing SHA-256 password hashes are upgraded when those users next sign in.

## Features and privacy

- Student and admin login are separate. Student signup always creates a student account. Additional admin signup accepts any valid email address and requires the existing local OCR name/DOB text-match and age checks; it does not use email OTP. OCR cannot establish that an identity document is genuine. Configure the first administrator with `BOOTSTRAP_ADMIN_EMAIL` and `BOOTSTRAP_ADMIN_PASSWORD`; if that email already belongs to an account, the configured password must verify before the account is promoted.
- Student signup requires the applicant to be under 23; admin signup requires the applicant to be at least 23. Age is calculated from the entered date of birth, which is used for the check and is not saved in the account database. This DOB check is not Aadhaar verification. Do not collect Aadhaar numbers here; actual Aadhaar verification requires an authorized UIDAI verification provider and separate privacy/legal review.
- Admin signup accepts a card photo for local OCR text matching against the entered name and DOB. The image is uploaded to this app server for in-memory processing only; it is not written to disk or the database, and OCR is not sent to a third-party service. Extracted text is not displayed, logged, or stored. OCR may be wrong and cannot establish that a document is genuine, belongs to the applicant, or is Aadhaar-authenticated. This is a text consistency check, not identity verification.
- Profiles can store roll number, department, year of study, and optional phone number. Roll numbers remain strings (including leading zeroes), are never returned by student-facing database queries, and are only searchable by a recently reauthenticated administrator. No roll-number format or uniqueness rule is assumed unless configured below.
- My Profile lets signed-in users verify their current password and generate ten one-time backup security codes. Save these codes securely; the app stores only password-strength hashes and cannot show them again. Forgot password accepts one unused security code; users who lose their codes must contact an administrator for identity-verified help.
- Private registered-item records are visible only to the owner or a recently reauthenticated admin. QR links contain only a random opaque token; the database stores a SHA-256 token hash. Public scans disclose no owner data. A QR is not proof of ownership.
- Claims and their ownership evidence are private to the claimant and admins. Only a reauthenticated admin can approve/reject claims or complete a handover. SQLite uniqueness constraints and an immediate transaction prevent a second handover for the same Found report.
- Lost/Found direction is separate from workflow (`Open`, `Under Review`, `Claim Pending`, `Approved for Handover`, `Returned`, `Closed`). Existing completion records migrate to `Closed`; other old reports migrate to `Open`, not `Returned`.
- Duplicate warnings compare only the current reporter's recent submissions and never block or delete records. Similarity matches rank Lost/Found pairs using explainable text, optional CLIP photo embeddings, category, location, and date scores. The scores are heuristics, not ownership decisions.
- New image uploads are decoded and re-encoded to JPEG with random filenames, format checks, a byte limit, and a pixel limit. Reports and photo files contain student-provided information; deploy only for a campus that is authorized to process it.

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_DATA_DIR` | App folder locally; `/var/data` in Docker | Writable directory for database, backups, photos, and data |
| `BOOTSTRAP_ADMIN_EMAIL` | unset | Email for first admin provisioning |
| `BOOTSTRAP_ADMIN_PASSWORD` | unset | Existing-account verification or initial admin password; store as a secret |
| `TESSERACT_CMD` | `tesseract` | Local Tesseract OCR executable path, if not on PATH |
| `ROLL_NUMBER_REGEX` | unset | Optional Python regular expression for the college's exact roll-number format |
| `ROLL_NUMBER_UNIQUE` | `false` | Set to `true` only if college rules require uniqueness; migration fails safely on existing duplicates |
| `APP_BASE_URL` | unset | Trusted HTTPS app URL used in QR links (HTTP localhost allowed for development) |
| `MAX_UPLOAD_BYTES` | `5242880` | Maximum decoded upload size in bytes (5 MiB) |
| `MAX_IMAGE_PIXELS` | `20000000` | Maximum decoded image pixels |
| `SESSION_IDLE_SECONDS` | `1800` | Streamlit inactivity timeout (minimum five minutes) |
| `IMAGE_MODEL` | `openai/clip-vit-base-patch32` | Hugging Face image-classification model |
| `DUPLICATE_WINDOW_HOURS` | `72` | Reporter-scoped duplicate warning window |
| `MATCH_WEIGHT_TEXT` | `0` | Optional non-negative matching weight; zero weights are ignored |
| `MATCH_WEIGHT_IMAGE` | `0` | Optional non-negative matching weight |
| `MATCH_WEIGHT_CATEGORY` | `0` | Optional non-negative matching weight |
| `MATCH_WEIGHT_LOCATION` | `0` | Optional non-negative matching weight |
| `MATCH_WEIGHT_DATE` | `0` | Optional non-negative matching weight |
| `SMTP_HOST` | unset | SMTP server for report notifications |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | unset | Optional SMTP authentication username |
| `SMTP_PASSWORD` | unset | Optional SMTP authentication password/app password |
| `SMTP_FROM_EMAIL` | `SMTP_USERNAME` | Sender address |
| `SMTP_USE_TLS` | `true` | Start TLS before SMTP authentication |
| `ADMIN_EMAILS` | unset | Comma-separated admin notification addresses; messages are sent separately |
| `HF_HOME` | Hugging Face default; `/var/data/huggingface` in Docker | Persistent cache location for downloaded model files |
| `PORT` | `8501` | Hosting platform port; Docker uses the host-provided value |

Roll-number settings must reflect actual college policy. Enabling uniqueness builds a partial unique index; if duplicates are present the app stops migration and tells the operator to resolve them first. Roll numbers are not included in QR payloads, emails, student report queries, or audit entries.

## Migrations, backups, and tests

On startup, the app applies repeatable, versioned SQLite migrations in a transaction and enables foreign keys for each connection. Before upgrading an existing database, it uses SQLite's online backup API and copies the item-photo directory into `APP_DATA_DIR/backups`. The first migration preserves existing user, report, email-log, and photo data. Keep off-host backups as well; a same-disk backup is not sufficient for disaster recovery.

Run the isolated test suite from this folder on Windows:

```powershell
py -3.12 -m pip install -r requirements.txt
py -3.12 -m unittest discover -s tests -v
```

Tests use temporary SQLite databases and do not reset or write to the app database.
For local admin signup OCR, install Tesseract OCR and ensure `tesseract.exe` is on `PATH`, or set `TESSERACT_CMD` to its full path. The Docker image installs the English Tesseract engine automatically.

## Deployment limitations and operational security

- Run one application instance when using SQLite. SQLite on a local persistent disk is not a multi-replica shared database. Back up the database and photos off-host and test restoration before production.
- Persistent local disk is required on Render to retain database, QR-linked data, photo files, and model cache. A container restart without a persistent disk loses these files. Streamlit Community Cloud's ephemeral filesystem is not suitable for durable production data without migrating storage.
- Streamlit account sessions are not a substitute for institutional SSO, email verification, MFA, or a formal identity lifecycle. Restrict who can reach the deployment, use strong unique passwords, TLS, managed secrets, rate limiting, and a reviewed admin onboarding/offboarding process.
- Admin sensitive actions require password reauthentication within five minutes. An app-level idle timeout clears the app session, but does not provide a hardened server-side session store or revoke copied browser cookies.
- QR tokens are bearer links: possession does not reveal the owner, but anyone holding a valid token can submit a found-item note. Rotate/revoke a code if it is shared or exposed.
- Email delivery is best-effort and failures are shown/logged; it is not a durable queue. Keep SMTP and Resend credentials private, and do not put roll numbers, serial numbers, evidence, or other sensitive details in email content.
- Similarity weights are configurable heuristics and have not been evaluated against labelled campus data. Human admin verification is always required before handover.
- Have the college review privacy notices, retention/deletion policy, access controls, threat model, SMTP provider, and data-protection obligations before handling real student data. This implementation is not a claim of production security certification.
