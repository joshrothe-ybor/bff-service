"""Database health check utilities."""

import asyncio
import logging
from typing import Dict, Any, Optional

from .config import get_database_config

logger = logging.getLogger(__name__)


class DatabaseHealthCheck:
    """Database health check utility."""

    def __init__(self) -> None:
        """Initialize the health check."""
        self._last_check_result: Optional[Dict[str, Any]] = None

    async def check_database_health(self) -> Dict[str, Any]:
        """Perform comprehensive database health check.
        
        Returns:
            Dict[str, Any]: Health check results
        """
        result = {
            "status": "healthy",
            "checks": {
                "connection": {"status": "unknown"},
                "pool": {"status": "unknown"},
                "migrations": {"status": "unknown"},
            },
            "details": {},
            "timestamp": None,
        }
        
        try:
            from datetime import datetime
            result["timestamp"] = datetime.utcnow().isoformat()
            
            db_config = get_database_config()
            
            # Test basic connection
            connection_healthy = await self._check_connection(db_config)
            result["checks"]["connection"]["status"] = "healthy" if connection_healthy else "unhealthy"
            
            # Check connection pool status
            pool_info = await self._check_pool_status(db_config)
            result["checks"]["pool"]["status"] = "healthy" if pool_info["healthy"] else "unhealthy"
            result["details"]["pool"] = pool_info
            
            # Check migrations status
            migration_info = await self._check_migrations_status(db_config)
            result["checks"]["migrations"]["status"] = "healthy" if migration_info["up_to_date"] else "unhealthy"
            result["details"]["migrations"] = migration_info
            
            # Overall status
            all_healthy = all(
                check["status"] == "healthy" 
                for check in result["checks"].values()
            )
            result["status"] = "healthy" if all_healthy else "unhealthy"
            
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            result["status"] = "unhealthy"
            result["error"] = str(e)
        
        self._last_check_result = result
        return result

    async def _check_connection(self, db_config) -> bool:
        """Check basic database connection.
        
        Args:
            db_config: Database configuration
            
        Returns:
            bool: True if connection is healthy
        """
        try:
            return await db_config.health_check()
        except Exception as e:
            logger.error(f"Connection health check failed: {e}")
            return False

    async def _check_pool_status(self, db_config) -> Dict[str, Any]:
        """Check connection pool status.
        
        Args:
            db_config: Database configuration
            
        Returns:
            Dict[str, Any]: Pool status information
        """
        try:
            engine = db_config.engine
            pool = engine.pool
            
            info = {
                "healthy": True,
                "size": getattr(pool, 'size', lambda: 0)(),
                "checked_in": getattr(pool, 'checkedin', lambda: 0)(),
                "checked_out": getattr(pool, 'checkedout', lambda: 0)(),
                "overflow": getattr(pool, 'overflow', lambda: 0)(),
                "invalid": getattr(pool, 'invalid', lambda: 0)(),
            }
            
            # Pool is unhealthy if all connections are checked out or invalid
            total_connections = info["checked_in"] + info["checked_out"]
            if total_connections > 0 and info["checked_in"] == 0:
                info["healthy"] = False
                info["warning"] = "No available connections in pool"
            
            return info
            
        except Exception as e:
            logger.error(f"Pool status check failed: {e}")
            return {
                "healthy": False,
                "error": str(e)
            }

    async def _check_migrations_status(self, db_config) -> Dict[str, Any]:
        """Check database migrations status.
        
        Args:
            db_config: Database configuration
            
        Returns:
            Dict[str, Any]: Migration status information
        """
        try:
            from alembic import command
            from alembic.config import Config
            from alembic.runtime.migration import MigrationContext
            from alembic.script import ScriptDirectory
            from pathlib import Path
            
            # Get the alembic.ini path
            alembic_ini = Path(__file__).parent.parent.parent / "alembic.ini"
            
            if not alembic_ini.exists():
                return {
                    "up_to_date": False,
                    "error": "Alembic configuration not found"
                }
            
            # Check current revision vs head
            async with db_config.engine.begin() as conn:
                def get_migration_info(connection):
                    context = MigrationContext.configure(connection)
                    current_rev = context.get_current_revision()
                    
                    # Get the script directory
                    alembic_cfg = Config(str(alembic_ini))
                    script_dir = ScriptDirectory.from_config(alembic_cfg)
                    head_rev = script_dir.get_current_head()
                    
                    return {
                        "current_revision": current_rev,
                        "head_revision": head_rev,
                        "up_to_date": current_rev == head_rev,
                    }
                
                info = await conn.run_sync(get_migration_info)
                return info
                
        except Exception as e:
            logger.error(f"Migration status check failed: {e}")
            return {
                "up_to_date": False,
                "error": str(e)
            }

    async def get_last_check_result(self) -> Optional[Dict[str, Any]]:
        """Get the last health check result.
        
        Returns:
            Optional[Dict[str, Any]]: Last check result or None
        """
        return self._last_check_result

    async def is_healthy(self) -> bool:
        """Quick health check.
        
        Returns:
            bool: True if database is healthy
        """
        try:
            db_config = get_database_config()
            return await db_config.health_check()
        except Exception:
            return False


# Global health check instance
_health_checker: Optional[DatabaseHealthCheck] = None


def get_health_checker() -> DatabaseHealthCheck:
    """Get the global health checker instance."""
    global _health_checker
    if _health_checker is None:
        _health_checker = DatabaseHealthCheck()
    return _health_checker 