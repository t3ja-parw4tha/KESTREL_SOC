#!/usr/bin/env python3
"""Create initial admin user. Run once after migrations.

Example:
    python -m scripts.create_admin
    # Or with custom username/password:
    python -m scripts.create_admin --username admin --password 'YourSecureP@ss1'
"""

import asyncio
import argparse
import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import select
from app.database import SessionLocal
from app.models import User
from app.security.auth import hash_password, validate_password_policy


async def main() -> None:
    parser = argparse.ArgumentParser(description="Create SOC platform admin user")
    parser.add_argument("--username", default="admin", help="Admin username")
    parser.add_argument("--password", default=None, help="Admin password (will prompt if not set)")
    parser.add_argument("--email", default="admin@localhost", help="Admin email")
    args = parser.parse_args()
    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Admin password: ")
        password2 = getpass.getpass("Confirm: ")
        if password != password2:
            print("Passwords do not match")
            sys.exit(1)
    validate_password_policy(password, args.username)
    async with SessionLocal() as db:
        r = await db.execute(select(User).where(User.username == args.username))
        if r.scalar_one_or_none():
            print(f"User {args.username} already exists")
            return
        user = User(
            username=args.username,
            email=args.email,
            password_hash=hash_password(password),
            role="admin",
            is_active=True,
            updated_at=datetime.now(timezone.utc),
        )
        db.add(user)
        await db.commit()
    print(f"Admin user '{args.username}' created.")


if __name__ == "__main__":
    asyncio.run(main())
