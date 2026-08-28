"""MongoDB client initialization and connection pooling for AWS Lambda."""

import logging
from typing import Optional
from pymongo import MongoClient
from pymongo.database import Database
from backend.utils.config import config

logger = logging.getLogger(__name__)

# Global client and db instances for connection reuse across warm Lambda invocations
_mongo_client: Optional[MongoClient] = None
_db_instance: Optional[Database] = None


def get_mongo_client() -> Optional[MongoClient]:
    """Get or create global MongoClient instance."""
    global _mongo_client
    if _mongo_client is None:
        if not config.MONGODB_URI:
            logger.warning("MONGODB_URI is not set. Database operations will use fallback or fail if unmocked.")
            return None
        try:
            _mongo_client = MongoClient(
                config.MONGODB_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
                maxPoolSize=50,
            )
            logger.info("MongoDB client connected successfully.")
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB Atlas: {str(e)}")
            _mongo_client = None
    return _mongo_client


def get_database(db_name: Optional[str] = None) -> Optional[Database]:
    """Get global Database instance."""
    global _db_instance
    if db_name is None:
        db_name = config.DB_NAME

    if _db_instance is not None:
        return _db_instance

    client = get_mongo_client()
    if client is not None:
        _db_instance = client[db_name]
        return _db_instance

    return None


def set_database(db: Database) -> None:
    """Set global database instance (useful for unit tests & mongomock)."""
    global _db_instance
    _db_instance = db
