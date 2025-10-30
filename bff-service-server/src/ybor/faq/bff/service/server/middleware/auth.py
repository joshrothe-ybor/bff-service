"""Authentication and authorization service for FastAPI REST endpoints."""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from jose import jwt
from fastapi import HTTPException, status
from passlib.context import CryptContext

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    
    def __init__(self, message: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(message)
        self.status_code = status_code


class AuthorizationError(Exception):
    """Raised when authorization fails."""
    
    def __init__(self, message: str, status_code: int = status.HTTP_403_FORBIDDEN):
        super().__init__(message)
        self.status_code = status_code


class JWTAuthenticator:
    """JWT-based authentication handler for FastAPI."""
    
    def __init__(
        self,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expire_minutes: int = 30,
        verify_exp: bool = True,
        verify_aud: bool = False,
        audience: Optional[str] = None,
        issuer: Optional[str] = None
    ):
        self.secret_key = secret_key
        self.algorithm = algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.verify_exp = verify_exp
        self.verify_aud = verify_aud
        self.audience = audience
        self.issuer = issuer
        
        # Initialize password context
        self.pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
        
        logger.info("JWT Authenticator initialized", algorithm=algorithm, token_expiry_minutes=access_token_expire_minutes)

    def verify_password(self, plain_password: str, hashed_password: str) -> bool:
        """Verify a plain password against a hashed password."""
        try:
            return self.pwd_context.verify(plain_password, hashed_password)
        except Exception as e:
            logger.error("Password verification failed", error=str(e))
            return False

    def get_password_hash(self, password: str) -> str:
        """Hash a password using bcrypt."""
        try:
            return self.pwd_context.hash(password)
        except Exception as e:
            logger.error("Password hashing failed", error=str(e))
            raise AuthenticationError("Failed to hash password")

    def create_access_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT access token."""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        
        if self.issuer:
            to_encode.update({"iss": self.issuer})
        
        if self.audience:
            to_encode.update({"aud": self.audience})
        
        try:
            encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
            logger.debug("JWT token created", subject=data.get("sub"), expires_at=expire.isoformat())
            return encoded_jwt
        except Exception as e:
            logger.error("JWT token creation failed", error=str(e))
            raise AuthenticationError("Failed to create access token")

    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode a JWT token."""
        try:
            options = {
                "verify_exp": self.verify_exp,
                "verify_aud": self.verify_aud,
            }
            
            audience = self.audience if self.verify_aud else None
            
            payload = jwt.decode(
                token, 
                self.secret_key, 
                algorithms=[self.algorithm],
                audience=audience,
                options=options
            )
            
            logger.debug("JWT token verified", subject=payload.get("sub"))
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            raise AuthenticationError("Token has expired", status.HTTP_401_UNAUTHORIZED)
        except jwt.InvalidTokenError as e:
            logger.warning("JWT token invalid", error=str(e))
            raise AuthenticationError("Invalid token", status.HTTP_401_UNAUTHORIZED)
        except Exception as e:
            logger.error("JWT token verification failed", error=str(e))
            raise AuthenticationError("Token verification failed", status.HTTP_401_UNAUTHORIZED)

    def create_refresh_token(self, data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
        """Create a JWT refresh token with longer expiration."""
        if expires_delta is None:
            expires_delta = timedelta(days=7)  # Default refresh token expiry: 7 days
        
        return self.create_access_token(data, expires_delta)


class AuthService:
    """High-level authentication service."""
    
    def __init__(self, jwt_authenticator: JWTAuthenticator):
        self.jwt_authenticator = jwt_authenticator
        
        # TODO: Replace with actual user repository/database
        # Placeholder test users for development
        self.test_users = {
            "admin": {
                "id": "admin-user-id",
                "username": "admin",
                "email": "admin@example.com",
                "hashed_password": self.jwt_authenticator.get_password_hash("admin123"),
                "roles": ["admin", "user"],
                "is_active": True
            },
            "user": {
                "id": "regular-user-id", 
                "username": "user",
                "email": "user@example.com",
                "hashed_password": self.jwt_authenticator.get_password_hash("user123"),
                "roles": ["user"],
                "is_active": True
            }
        }
        
        logger.info("Auth Service initialized with test users", user_count=len(self.test_users))

    async def authenticate_user(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate a user with username and password."""
        try:
            user = self.test_users.get(username)
            if not user:
                logger.warning("User not found", username=username)
                return None
            
            if not user["is_active"]:
                logger.warning("User account disabled", username=username)
                return None
            
            if not self.jwt_authenticator.verify_password(password, user["hashed_password"]):
                logger.warning("Password verification failed", username=username)
                return None
            
            logger.info("User authenticated successfully", username=username, user_id=user["id"])
            return user
        except Exception as e:
            logger.error("User authentication failed", username=username, error=str(e))
            return None

    async def create_access_token(self, user_data: Dict[str, Any]) -> str:
        """Create an access token for the authenticated user."""
        token_data = {
            "sub": user_data["id"],
            "username": user_data["username"],
            "email": user_data["email"],
            "roles": user_data["roles"],
            "token_type": "access"
        }
        return self.jwt_authenticator.create_access_token(token_data)

    async def create_refresh_token(self, user_data: Dict[str, Any]) -> str:
        """Create a refresh token for the authenticated user."""
        token_data = {
            "sub": user_data["id"],
            "username": user_data["username"],
            "token_type": "refresh"
        }
        return self.jwt_authenticator.create_refresh_token(token_data)

    async def verify_access_token(self, token: str) -> Dict[str, Any]:
        """Verify an access token and return user data."""
        payload = self.jwt_authenticator.verify_token(token)
        
        if payload.get("token_type") != "access":
            raise AuthenticationError("Invalid token type")
        
        return payload

    async def verify_refresh_token(self, token: str) -> Dict[str, Any]:
        """Verify a refresh token and return user data."""
        payload = self.jwt_authenticator.verify_token(token)
        
        if payload.get("token_type") != "refresh":
            raise AuthenticationError("Invalid token type")
        
        return payload

    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user by ID (for token validation)."""
        try:
            for user in self.test_users.values():
                if user["id"] == user_id:
                    return user
            return None
        except Exception as e:
            logger.error("Failed to get user by ID", user_id=user_id, error=str(e))
            return None

    def check_user_roles(self, user_data: Dict[str, Any], required_roles: list[str]) -> bool:
        """Check if user has required roles."""
        user_roles = user_data.get("roles", [])
        return any(role in user_roles for role in required_roles)

    def check_user_permissions(self, user_data: Dict[str, Any], required_permissions: list[str]) -> bool:
        """Check if user has required permissions (role-based for now)."""
        # Simple role-based permissions for now
        # TODO: Implement more granular permission system
        user_roles = user_data.get("roles", [])
        
        # Admin has all permissions
        if "admin" in user_roles:
            return True
        
        # Map permissions to roles
        permission_role_map = {
            "read:users": ["user", "admin"],
            "write:users": ["admin"],
            "read:bff": ["user", "admin"],
            "write:bff": ["user", "admin"],
            "delete:bff": ["admin"]
        }
        
        return any(
            any(role in user_roles for role in permission_role_map.get(permission, []))
            for permission in required_permissions
        )


# Global instances - these should be dependency injected properly in production
_jwt_authenticator: Optional[JWTAuthenticator] = None
_auth_service: Optional[AuthService] = None


def get_jwt_authenticator() -> JWTAuthenticator:
    """Get JWT authenticator instance (dependency injection)."""
    global _jwt_authenticator
    if _jwt_authenticator is None:
        from ..config.settings import get_settings
        settings = get_settings()
        _jwt_authenticator = JWTAuthenticator(
            secret_key=settings.jwt_secret_key,
            algorithm=settings.jwt_algorithm,
            access_token_expire_minutes=settings.jwt_access_token_expire_minutes
        )
    return _jwt_authenticator


def get_auth_service() -> AuthService:
    """Get auth service instance (dependency injection)."""
    global _auth_service
    if _auth_service is None:
        jwt_authenticator = get_jwt_authenticator()
        _auth_service = AuthService(jwt_authenticator)
    return _auth_service 