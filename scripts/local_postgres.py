"""Optional isolated PostgreSQL instance using locally installed binaries.

Usage: .venv/Scripts/python scripts/local_postgres.py start --bin "C:/Program Files/PostgreSQL/18/bin"
This only manages .runtime/postgres; it never touches a system PostgreSQL service.
"""

import argparse
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import psycopg
from dotenv import dotenv_values, set_key
from psycopg import sql
from sqlalchemy.engine import URL

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"
DATA = RUNTIME / "postgres"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "stop"])
    parser.add_argument(
        "--bin", default="C:/Program Files/PostgreSQL/18/bin" if os.name == "nt" else ""
    )
    parser.add_argument("--port", type=int, default=55432)
    args = parser.parse_args()
    binary = Path(args.bin) if args.bin else Path(shutil.which("pg_ctl") or "").parent
    suffix = ".exe" if os.name == "nt" else ""
    pg_ctl = str(binary / f"pg_ctl{suffix}")
    if not Path(pg_ctl).is_file():
        parser.error(
            "PostgreSQL binaries not found. Supply --bin or use Docker Compose."
        )
    if args.action == "stop":
        subprocess.run(
            [pg_ctl, "-D", str(DATA), "-m", "fast", "-w", "stop"], check=True
        )
        return
    values = dotenv_values(ROOT / ".env")
    user = values.get("POSTGRES_USER")
    password = values.get("POSTGRES_PASSWORD")
    database = values.get("POSTGRES_DB")
    if not all((user, password, database)):
        parser.error("Run scripts/setup_env.py first.")
    RUNTIME.mkdir(exist_ok=True)
    if not (DATA / "PG_VERSION").exists():
        with tempfile.NamedTemporaryFile(
            mode="w", dir=RUNTIME, delete=False, encoding="utf-8"
        ) as file:
            file.write(str(password))
            password_file = Path(file.name)
        try:
            subprocess.run(
                [
                    str(binary / f"initdb{suffix}"),
                    "-D",
                    str(DATA),
                    "-U",
                    str(user),
                    "--auth=scram-sha-256",
                    "--encoding=UTF8",
                    "--locale=C",
                    f"--pwfile={password_file}",
                ],
                check=True,
            )
        finally:
            password_file.unlink(missing_ok=True)
    status = subprocess.run(
        [pg_ctl, "-D", str(DATA), "status"], capture_output=True, check=False
    )
    if status.returncode != 0:
        subprocess.run(
            [
                pg_ctl,
                "-D",
                str(DATA),
                "-l",
                str(RUNTIME / "postgres.log"),
                "-o",
                f"-h 127.0.0.1 -p {args.port}",
                "-w",
                "start",
            ],
            check=True,
        )
    with psycopg.connect(
        host="127.0.0.1",
        port=args.port,
        user=user,
        password=password,
        dbname="postgres",
        autocommit=True,
    ) as connection:
        if not connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s", (database,)
        ).fetchone():
            connection.execute(
                sql.SQL("CREATE DATABASE {}").format(sql.Identifier(str(database)))
            )
    url = URL.create(
        "postgresql+psycopg",
        username=user,
        password=password,
        host="127.0.0.1",
        port=args.port,
        database=database,
    )
    set_key(ROOT / ".env", "POSTGRES_PORT", str(args.port), quote_mode="never")
    set_key(
        ROOT / ".env",
        "DATABASE_URL",
        url.render_as_string(hide_password=False),
        quote_mode="never",
    )
    print(
        f"Isolated PostgreSQL ready on 127.0.0.1:{args.port}. .env updated; no system service changed."
    )


if __name__ == "__main__":
    main()
