from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

# Database connection pooling and connection arguments
connect_args = {}
database_url = settings.DATABASE_URL

try:
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        engine = create_engine(database_url, connect_args=connect_args)
    else:
        engine = create_engine(database_url, pool_pre_ping=True)
        # Quick check connection
        with engine.connect() as conn:
            pass
except Exception as e:
    import sys
    print(f"WARNING: PostgreSQL connection failed ({e}). Falling back to local SQLite database: sqlite:///./cyber_monkey.db", file=sys.stderr)
    database_url = "sqlite:///./cyber_monkey.db"
    connect_args["check_same_thread"] = False
    engine = create_engine(database_url, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# DB Dependency injection helper
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
