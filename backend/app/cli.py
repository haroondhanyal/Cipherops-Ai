import argparse
from getpass import getpass

from sqlalchemy import select

from .database import SessionLocal
from .models import Role, User
from .security import hash_password


def main():
    parser = argparse.ArgumentParser(
        description="Create a CipherOps user without storing a default password"
    )
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument(
        "--role", default="SOC Analyst", choices=["SOC Analyst", "Security Administrator", "CISO"]
    )
    args = parser.parse_args()
    password = getpass("Password: ")
    if len(password) < 12:
        raise SystemExit("Use a password with at least 12 characters")
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.email == args.email.lower())):
            raise SystemExit("A user with that email already exists")
        role = db.scalar(select(Role).where(Role.name == args.role))
        if not role:
            raise SystemExit("Run the API once to initialize the built-in roles first")
        db.add(
            User(
                email=args.email.lower(),
                full_name=args.name,
                password_hash=hash_password(password),
                roles=[role],
            )
        )
        db.commit()
    print(f"Created {args.role} user {args.email}")


if __name__ == "__main__":
    main()
