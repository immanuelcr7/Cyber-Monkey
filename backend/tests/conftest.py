import pytest
from app.database.session import Base, engine

@pytest.fixture(autouse=True, scope="function")
def ensure_test_database_tables():
    """Ensures all database tables exist before each test runs."""
    Base.metadata.create_all(bind=engine)
    yield
