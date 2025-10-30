"""REST HTTP client for Bff Service."""

from typing import Optional, Dict, Any, Union
import json
import time
from datetime import datetime, timedelta
from abc import ABC, abstractmethod

import httpx
import structlog

# Import DTOs from API models
from ybor.faq.bff.service.api.models import (
    CreateBffResponse,
    DeleteBffRequest,
    DeleteBffResponse,
    BffDto,
    GetBffRequest,
    GetBffResponse,
    GetBffsRequest,
    GetBffsResponse,
    UpdateBffResponse,
)

logger = structlog.get_logger(__name__)


class AuthenticationScheme(ABC):
    """Abstract base class for authentication schemes."""
    
    @abstractmethod
    async def apply_auth(self, headers: Dict[str, str]) -> None:
        """Apply authentication to request headers."""
        pass
    
    @abstractmethod
    async def handle_auth_error(self, response: httpx.Response) -> bool:
        """Handle authentication errors. Return True if retry should be attempted."""
        pass


class BearerTokenAuth(AuthenticationScheme):
    """Bearer token authentication scheme."""
    
    def __init__(self, token: str):
        self.token = token
    
    async def apply_auth(self, headers: Dict[str, str]) -> None:
        headers["Authorization"] = f"Bearer {self.token}"
    
    async def handle_auth_error(self, response: httpx.Response) -> bool:
        # Bearer tokens typically can't be refreshed automatically
        return False


class JWTAuth(AuthenticationScheme):
    """JWT authentication with automatic refresh capabilities."""
    
    def __init__(
        self, 
        access_token: str, 
        refresh_token: Optional[str] = None,
        token_url: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ):
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.token_url = token_url
        self.expires_at = expires_at
        self._refresh_lock = False
    
    async def apply_auth(self, headers: Dict[str, str]) -> None:
        # Check if token needs refresh before applying
        if self._needs_refresh():
            await self._refresh_token()
        headers["Authorization"] = f"Bearer {self.access_token}"
    
    async def handle_auth_error(self, response: httpx.Response) -> bool:
        """Handle auth errors by attempting token refresh."""
        if response.status_code == 401 and self.refresh_token and not self._refresh_lock:
            try:
                await self._refresh_token()
                return True  # Retry the request
            except Exception as e:
                logger.error("Failed to refresh token", error=str(e))
        return False
    
    def _needs_refresh(self) -> bool:
        """Check if token needs refresh (expires within 5 minutes)."""
        if not self.expires_at:
            return False
        return datetime.utcnow() + timedelta(minutes=5) >= self.expires_at
    
    async def _refresh_token(self) -> None:
        """Refresh the access token using refresh token."""
        if not self.refresh_token or not self.token_url or self._refresh_lock:
            return
        
        self._refresh_lock = True
        try:
            logger.info("Refreshing JWT token")
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.token_url,
                    json={"refresh_token": self.refresh_token}
                )
                
                if response.status_code == 200:
                    token_data = response.json()
                    self.access_token = token_data["access_token"]
                    if "expires_in" in token_data:
                        self.expires_at = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])
                    if "refresh_token" in token_data:
                        self.refresh_token = token_data["refresh_token"]
                    logger.info("JWT token refreshed successfully")
                else:
                    raise BffServiceClientError(f"Token refresh failed: {response.status_code}")
        finally:
            self._refresh_lock = False


class APIKeyAuth(AuthenticationScheme):
    """API Key authentication scheme."""
    
    def __init__(self, api_key: str, header_name: str = "X-API-Key"):
        self.api_key = api_key
        self.header_name = header_name
    
    async def apply_auth(self, headers: Dict[str, str]) -> None:
        headers[self.header_name] = self.api_key
    
    async def handle_auth_error(self, response: httpx.Response) -> bool:
        # API keys typically can't be refreshed automatically
        return False


class BasicAuth(AuthenticationScheme):
    """HTTP Basic authentication scheme."""
    
    def __init__(self, username: str, password: str):
        import base64
        credentials = f"{username}:{password}"
        self.encoded_credentials = base64.b64encode(credentials.encode()).decode()
    
    async def apply_auth(self, headers: Dict[str, str]) -> None:
        headers["Authorization"] = f"Basic {self.encoded_credentials}"
    
    async def handle_auth_error(self, response: httpx.Response) -> bool:
        # Basic auth credentials typically can't be refreshed
        return False


class AuthenticationManager:
    """Manages authentication for HTTP client requests."""
    
    def __init__(self, auth_scheme: Optional[AuthenticationScheme] = None):
        self.auth_scheme = auth_scheme
        self._retry_count = 0
        self._max_retries = 1
    
    def set_auth_scheme(self, auth_scheme: AuthenticationScheme) -> None:
        """Set the authentication scheme."""
        self.auth_scheme = auth_scheme
        logger.info("Authentication scheme updated", scheme_type=type(auth_scheme).__name__)
    
    def clear_auth(self) -> None:
        """Clear the current authentication scheme."""
        self.auth_scheme = None
        logger.info("Authentication cleared")
    
    async def apply_auth(self, headers: Dict[str, str]) -> None:
        """Apply authentication to request headers."""
        if self.auth_scheme:
            await self.auth_scheme.apply_auth(headers)
    
    async def handle_auth_error(self, response: httpx.Response) -> bool:
        """Handle authentication errors with potential retry."""
        if not self.auth_scheme:
            return False
        
        if self._retry_count >= self._max_retries:
            self._retry_count = 0
            return False
        
        should_retry = await self.auth_scheme.handle_auth_error(response)
        if should_retry:
            self._retry_count += 1
            logger.info("Retrying request after auth error", retry_count=self._retry_count)
        else:
            self._retry_count = 0
        
        return should_retry


class BffServiceClientError(Exception):
    """Base exception for Bff service client errors."""
    
    def __init__(self, message: str, status_code: Optional[int] = None, response_body: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class BffServiceClient:
    """Client for connecting to the Bff Service REST API."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        timeout: float = 30.0,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        auth_scheme: Optional[AuthenticationScheme] = None
    ) -> None:
        """Initialize the Bff Service client.
        
        Args:
            base_url: Base URL for the REST API (e.g., "http://localhost:8000")
            timeout: Default timeout for requests in seconds
            headers: Optional default headers to include with requests
            verify_ssl: Whether to verify SSL certificates
            follow_redirects: Whether to follow HTTP redirects
            auth_scheme: Optional authentication scheme to use
        """
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.default_headers = headers or {}
        
        # Set up default headers
        self.default_headers.setdefault('Content-Type', 'application/json')
        self.default_headers.setdefault('Accept', 'application/json')
        
        # Initialize authentication manager
        self.auth_manager = AuthenticationManager(auth_scheme)
        
        # Create httpx client with configuration
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            headers=self.default_headers,
            verify=verify_ssl,
            follow_redirects=follow_redirects
        )
        
        logger.info(
            "Bff Service client initialized",
            base_url=base_url,
            timeout=timeout,
            verify_ssl=verify_ssl,
            has_auth=auth_scheme is not None
        )

    @classmethod
    def create(cls, base_url: str, timeout: float = 30.0) -> "BffServiceClient":
        """Factory method to create a client instance.
        
        Args:
            base_url: Base URL for the REST API
            timeout: Request timeout in seconds
            
        Returns:
            Configured client instance
        """
        return cls(base_url=base_url, timeout=timeout)

    async def _make_authenticated_request(
        self, 
        method: str, 
        url: str, 
        **kwargs
    ) -> httpx.Response:
        """Make an authenticated HTTP request with automatic retry on auth failure.
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            url: Request URL
            **kwargs: Additional arguments for the HTTP request
            
        Returns:
            HTTP response
            
        Raises:
            BffServiceClientError: If the request fails
        """
        # Prepare headers with authentication
        request_headers = kwargs.get('headers', {}).copy()
        await self.auth_manager.apply_auth(request_headers)
        kwargs['headers'] = request_headers
        
        # Make the initial request
        response = await self.client.request(method, url, **kwargs)
        
        # Handle authentication errors with potential retry
        if response.status_code == 401:
            should_retry = await self.auth_manager.handle_auth_error(response)
            if should_retry:
                # Reapply authentication and retry
                request_headers = kwargs.get('headers', {}).copy()
                await self.auth_manager.apply_auth(request_headers)
                kwargs['headers'] = request_headers
                response = await self.client.request(method, url, **kwargs)
        
        return response

    # Authentication Management Methods
    
    def set_authentication(self, auth_scheme: AuthenticationScheme) -> None:
        """Set the authentication scheme for this client.
        
        Args:
            auth_scheme: Authentication scheme to use
        """
        self.auth_manager.set_auth_scheme(auth_scheme)
    
    def set_jwt_auth(
        self, 
        access_token: str, 
        refresh_token: Optional[str] = None,
        token_url: Optional[str] = None,
        expires_at: Optional[datetime] = None
    ) -> None:
        """Set JWT authentication with optional refresh capabilities.
        
        Args:
            access_token: JWT access token
            refresh_token: Optional refresh token for automatic token refresh
            token_url: Optional URL for token refresh endpoint
            expires_at: Optional token expiration time
        """
        jwt_auth = JWTAuth(access_token, refresh_token, token_url, expires_at)
        self.set_authentication(jwt_auth)
    
    def set_bearer_token(self, token: str) -> None:
        """Set simple bearer token authentication.
        
        Args:
            token: Bearer token to use
        """
        bearer_auth = BearerTokenAuth(token)
        self.set_authentication(bearer_auth)
    
    def set_api_key(self, api_key: str, header_name: str = "X-API-Key") -> None:
        """Set API key authentication.
        
        Args:
            api_key: API key to use
            header_name: Header name for the API key (default: X-API-Key)
        """
        api_key_auth = APIKeyAuth(api_key, header_name)
        self.set_authentication(api_key_auth)
    
    def set_basic_auth(self, username: str, password: str) -> None:
        """Set HTTP Basic authentication.
        
        Args:
            username: Username for basic auth
            password: Password for basic auth
        """
        basic_auth = BasicAuth(username, password)
        self.set_authentication(basic_auth)
    
    def clear_authentication(self) -> None:
        """Clear the current authentication scheme."""
        self.auth_manager.clear_auth()
    
    async def login(self, username: str, password: str) -> Dict[str, Any]:
        """Perform login and automatically set JWT authentication.
        
        Args:
            username: Username for login
            password: Password for login
            
        Returns:
            Login response data
            
        Raises:
            BffServiceClientError: If login fails
        """
        try:
            # Temporarily clear auth for login request
            original_auth = self.auth_manager.auth_scheme
            self.auth_manager.clear_auth()
            
            response = await self.client.post(
                f"{self.base_url}/auth/login",
                json={"username": username, "password": password}
            )
            
            if response.status_code == 200:
                login_data = response.json()
                
                # Set up JWT authentication with the received tokens
                access_token = login_data.get("access_token")
                refresh_token = login_data.get("refresh_token")
                expires_in = login_data.get("expires_in")
                
                if access_token:
                    expires_at = None
                    if expires_in:
                        expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
                    
                    self.set_jwt_auth(
                        access_token=access_token,
                        refresh_token=refresh_token,
                        token_url=f"{self.base_url}/auth/refresh",
                        expires_at=expires_at
                    )
                    
                    logger.info("Login successful, JWT authentication configured")
                
                return login_data
            else:
                # Restore original auth if login failed
                if original_auth:
                    self.auth_manager.set_auth_scheme(original_auth)
                await self._handle_error_response(response, "login")
                
        except httpx.RequestError as e:
            logger.error("Network error during login", error=str(e))
            raise BffServiceClientError(f"Network error during login: {str(e)}")
        except Exception as e:
            logger.error("Unexpected error during login", error=str(e), exc_info=True)
            raise BffServiceClientError(f"Unexpected error during login: {str(e)}")

    async def create_bff(self, bff: BffDto) -> CreateBffResponse:
        """Create a new bff.
        
        Args:
            bff: Bff data to create
            
        Returns:
            Response containing the created bff
            
        Raises:
            BffServiceClientError: If the API call fails
        """
        logger.info("Creating bff", name=bff.name)
        
        try:
            # Convert DTO to JSON payload
            payload = bff.model_dump(exclude_none=True)
            
            # Make authenticated REST API call
            response = await self._make_authenticated_request(
                "POST",
                f"{self.base_url}/api/v1/bffs",
                json=payload
            )
            
            # Handle response
            if response.status_code == 201:
                response_data = response.json()
                result = CreateBffResponse(**response_data)
                logger.info("Bff created successfully", bff_id=result.bff.id)
                return result
            else:
                await self._handle_error_response(response, "creating bff")
                
        except httpx.RequestError as e:
            logger.error("Network error creating bff", error=str(e))
            raise BffServiceClientError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error("Unexpected error creating bff", error=str(e), exc_info=True)
            raise BffServiceClientError(f"Unexpected error: {str(e)}")

    async def get_bffs(self, request: GetBffsRequest) -> GetBffsResponse:
        """Get a paginated list of bffs.
        
        Args:
            request: Pagination request parameters
            
        Returns:
            Response containing bffs and pagination metadata
            
        Raises:
            BffServiceClientError: If the API call fails
        """
        logger.info("Getting bffs", start_page=request.start_page, page_size=request.page_size)
        
        try:
            # Build query parameters
            params = {
                "page": request.start_page,
                "size": request.page_size
            }
            if request.status:
                params["status"] = request.status
            
            # Make authenticated REST API call
            response = await self._make_authenticated_request(
                "GET",
                f"{self.base_url}/api/v1/bffs",
                params=params
            )
            
            # Handle response
            if response.status_code == 200:
                response_data = response.json()
                result = GetBffsResponse(**response_data)
                logger.info("Bffs retrieved successfully", count=len(result.bffs))
                return result
            else:
                await self._handle_error_response(response, "getting bffs")
                
        except httpx.RequestError as e:
            logger.error("Network error getting bffs", error=str(e))
            raise BffServiceClientError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error("Unexpected error getting bffs", error=str(e), exc_info=True)
            raise BffServiceClientError(f"Unexpected error: {str(e)}")

    async def get_bff(self, request: GetBffRequest) -> GetBffResponse:
        """Get a single bff by ID.
        
        Args:
            request: Request containing the bff ID
            
        Returns:
            Response containing the requested bff
            
        Raises:
            BffServiceClientError: If the API call fails
        """
        logger.info("Getting bff", bff_id=request.id)
        
        try:
            # Make authenticated REST API call
            response = await self._make_authenticated_request(
                "GET",
                f"{self.base_url}/api/v1/bffs/{request.id}"
            )
            
            # Handle response
            if response.status_code == 200:
                response_data = response.json()
                result = GetBffResponse(**response_data)
                logger.info("Bff retrieved successfully", bff_id=result.bff.id)
                return result
            else:
                await self._handle_error_response(response, f"getting bff {request.id}")
                
        except httpx.RequestError as e:
            logger.error("Network error getting bff", error=str(e), bff_id=request.id)
            raise BffServiceClientError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error("Unexpected error getting bff", error=str(e), bff_id=request.id, exc_info=True)
            raise BffServiceClientError(f"Unexpected error: {str(e)}")

    async def update_bff(self, bff: BffDto) -> UpdateBffResponse:
        """Update an existing bff.
        
        Args:
            bff: Updated bff data
            
        Returns:
            Response containing the updated bff
            
        Raises:
            BffServiceClientError: If the API call fails
        """
        if not bff.id:
            raise BffServiceClientError("Bff ID is required for update operations")
            
        logger.info("Updating bff", bff_id=bff.id)
        
        try:
            # Convert DTO to JSON payload (exclude ID from body, it's in the URL)
            payload = bff.model_dump(exclude_none=True, exclude={'id'})
            
            # Make authenticated REST API call
            response = await self._make_authenticated_request(
                "PUT",
                f"{self.base_url}/api/v1/bffs/{bff.id}",
                json=payload
            )
            
            # Handle response
            if response.status_code == 200:
                response_data = response.json()
                result = UpdateBffResponse(**response_data)
                logger.info("Bff updated successfully", bff_id=result.bff.id)
                return result
            else:
                await self._handle_error_response(response, f"updating bff {bff.id}")
                
        except httpx.RequestError as e:
            logger.error("Network error updating bff", error=str(e), bff_id=bff.id)
            raise BffServiceClientError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error("Unexpected error updating bff", error=str(e), bff_id=bff.id, exc_info=True)
            raise BffServiceClientError(f"Unexpected error: {str(e)}")

    async def delete_bff(self, request: DeleteBffRequest) -> DeleteBffResponse:
        """Delete a bff by ID.
        
        Args:
            request: Request containing the bff ID to delete
            
        Returns:
            Response with confirmation message
            
        Raises:
            BffServiceClientError: If the API call fails
        """
        logger.info("Deleting bff", bff_id=request.id)
        
        try:
            # Make authenticated REST API call
            response = await self._make_authenticated_request(
                "DELETE",
                f"{self.base_url}/api/v1/bffs/{request.id}"
            )
            
            # Handle response
            if response.status_code == 200:
                response_data = response.json()
                result = DeleteBffResponse(**response_data)
                logger.info("Bff deleted successfully", message=result.message)
                return result
            else:
                await self._handle_error_response(response, f"deleting bff {request.id}")
                
        except httpx.RequestError as e:
            logger.error("Network error deleting bff", error=str(e), bff_id=request.id)
            raise BffServiceClientError(f"Network error: {str(e)}")
        except Exception as e:
            logger.error("Unexpected error deleting bff", error=str(e), bff_id=request.id, exc_info=True)
            raise BffServiceClientError(f"Unexpected error: {str(e)}")

    async def close(self) -> None:
        """Close the HTTP client."""
        if self.client:
            await self.client.aclose()
            logger.info("HTTP client closed")

    async def __aenter__(self) -> "BffServiceClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()

    # Synchronous context manager support for backward compatibility
    def __enter__(self) -> "BffServiceClient":
        """Synchronous context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Synchronous context manager exit."""
        # Note: This is not ideal for async clients, but provided for compatibility
        # Users should prefer the async context manager
        import asyncio
        try:
            asyncio.get_running_loop()
            logger.warning("Using synchronous context manager in async context. Consider using async context manager.")
        except RuntimeError:
            # No event loop running, we can create one
            asyncio.run(self.close())

    async def _handle_error_response(self, response: httpx.Response, operation: str) -> None:
        """Handle error responses from the API.
        
        Args:
            response: The HTTP response object
            operation: Description of the operation that failed
            
        Raises:
            BffServiceClientError: Always raises with appropriate error message
        """
        try:
            error_data = response.json()
            error_message = error_data.get('error', {}).get('message', f'HTTP {response.status_code}')
        except (json.JSONDecodeError, KeyError):
            error_message = f"HTTP {response.status_code}: {response.text}"
        
        logger.error(
            f"API error {operation}",
            status_code=response.status_code,
            error_message=error_message,
            response_body=response.text
        )
        
        raise BffServiceClientError(
            f"API error {operation}: {error_message}",
            status_code=response.status_code,
            response_body=response.text
        )

    def set_auth_token(self, token: str) -> None:
        """Set authentication token for future requests.
        
        Args:
            token: JWT or API token to use for authentication
        
        Note: This method is deprecated. Use set_bearer_token() for new code.
        """
        logger.warning("set_auth_token() is deprecated. Use set_bearer_token() instead.")
        self.set_bearer_token(token)

    def remove_auth_token(self) -> None:
        """Remove authentication token from future requests.
        
        Note: This method is deprecated. Use clear_authentication() for new code.
        """
        logger.warning("remove_auth_token() is deprecated. Use clear_authentication() instead.")
        self.clear_authentication()

    def set_header(self, name: str, value: str) -> None:
        """Set a custom header for future requests.
        
        Args:
            name: Header name
            value: Header value
        """
        self.client.headers[name] = value
        logger.debug("Custom header set", header_name=name)

    def remove_header(self, name: str) -> None:
        """Remove a custom header from future requests.
        
        Args:
            name: Header name to remove
        """
        self.client.headers.pop(name, None)
        logger.debug("Custom header removed", header_name=name)