import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:////ca-data/certledger.db")

# SQLite: ensure its directory exists and disable the same-thread check
if DATABASE_URL.startswith("sqlite"):
    _db_file = DATABASE_URL.replace("sqlite:///", "")
    os.makedirs(os.path.dirname(_db_file), exist_ok=True)
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(DATABASE_URL, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
