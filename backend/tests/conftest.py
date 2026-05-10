"""Pytest configuration for testing."""
import pytest
from app.database import Base


@pytest.fixture
async def test_db():
    """
    Create test database session.
    """
    # TODO: Create test database and session
    pass


@pytest.fixture
async def test_client():
    """
    Create test HTTP client.
    """
    # TODO: Create FastAPI test client
    pass
