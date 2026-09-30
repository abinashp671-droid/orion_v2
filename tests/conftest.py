"""Pytest configuration and global fixtures for ORION v2 test suite."""

import pytest
import pytest_asyncio
from app.core.config import settings
from app.core.database import init_db

# Ensure a dedicated test database path across all test modules
TEST_DB_PATH = settings.DATA_DIR / "test_orion.db"
settings.DATABASE_PATH = TEST_DB_PATH


@pytest_asyncio.fixture(autouse=True)
async def setup_orion_test_db():
    """Global autouse fixture to initialize clean SQLite test schema for every test."""
    await init_db()
    yield
