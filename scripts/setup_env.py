"""Create local environment files without overwriting existing configuration."""

import secrets
from pathlib import Path

from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parents[1]
destination = ROOT / ".env"
if not destination.exists():
    password = secrets.token_urlsafe(32)
    contents = (ROOT / ".env.example").read_text(encoding="utf-8")
    contents = contents.replace(
        "POSTGRES_PASSWORD=\n", f"POSTGRES_PASSWORD={password}\n"
    )
    contents = contents.replace(
        "DATABASE_URL=\n",
        f"DATABASE_URL=postgresql+psycopg://dast:{password}@127.0.0.1:5432/dast\n",
    )
    destination.write_text(contents, encoding="utf-8")
    print("Created .env with a generated local database password.")
else:
    contents = destination.read_text(encoding="utf-8")
if "DAST_SECRET_KEY=" not in contents:
    contents += f"\nDAST_SECRET_KEY={Fernet.generate_key().decode('ascii')}\n"
elif "DAST_SECRET_KEY=\n" in contents:
    contents = contents.replace(
        "DAST_SECRET_KEY=\n",
        f"DAST_SECRET_KEY={Fernet.generate_key().decode('ascii')}\n",
    )
destination.write_text(contents, encoding="utf-8")
frontend = ROOT / "frontend/.env"
if not frontend.exists():
    frontend.write_text((ROOT / "frontend/.env.example").read_text(), encoding="utf-8")
print("Environment files ready; existing files were preserved.")
