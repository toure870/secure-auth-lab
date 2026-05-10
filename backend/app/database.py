"""Database configuration and initialization."""
import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)
from sqlalchemy.orm import declarative_base

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Base class for all models
Base = declarative_base()

# Engine and session maker
engine = None
AsyncSessionLocal = None


async def init_db():
    """
    Initialize database engine and session maker.
    
    Call this on application startup.
    """
    global engine, AsyncSessionLocal
    
    # Create async engine
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.SQLALCHEMY_ECHO,
        pool_size=20,
        max_overflow=40,
        pool_pre_ping=True,  # Test connections before using
        future=True,
    )
    
    # Create session maker
    AsyncSessionLocal = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
    )
    
    logger.info("Database initialized")


async def close_db():
    """
    Close database connections.
    
    Call this on application shutdown.
    """
    global engine
    
    if engine:
        await engine.dispose()
        logger.info("Database connections closed")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency to get database session.
    
    Usage:
        @app.get("/")
        async def route(db: AsyncSession = Depends(get_db)):
            ...
    
    Yields:
        AsyncSession instance
    """
    if not AsyncSessionLocal:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception as e:
            await session.rollback()
            logger.error(f"Database error: {str(e)}", exc_info=True)
            raise
        finally:
            await session.close()


def get_db_context():
    """
    Get database session for use outside of FastAPI context.
    
    Usage:
        async with get_db_context() as session:
            ...
    """
    return AsyncSessionLocal()


async def create_tables():
    """
    Create all database tables.
    
    Only needed for development. Use Alembic migrations in production.
    """
    if not engine:
        await init_db()
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("All tables created")


async def drop_tables():
    """
    Drop all database tables.
    
    WARNING: This deletes all data. Use only in development!
    """
    if not engine:
        await init_db()
    
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("All tables dropped")
