from fastapi import FastAPI, HTTPException
from collections import defaultdict, deque
import time
from typing import Dict
from fastapi import Depends
from fastapi.security import APIKeyHeader

# Code adapted from: Mojibata (MJ) Michael, Medium (2025)
# Source: https://mjmichael.medium.com/sliding-window-log-algorithm-a-dive-with-implementations-in-golang-and-python-47e451939f60

app = FastAPI(title="Sliding Window Log Rate Limiter API")


# Configuration
WINDOW_SIZE = 60  # Time window in seconds
MAX_REQUESTS = 5  # Maximum requests allowed in the window


# Rate limiter class
class SlidingWindowLog:
    def __init__(self, window_size: float, max_requests: int):
        """
        Initialize the Sliding Window Log rate limiter.
        
        :param window_size: Size of the time window in seconds
        :param max_requests: Maximum number of requests allowed in the window
        """
        self.window_size = window_size
        self.max_requests = max_requests
        # Store request timestamps for each client
        self.request_logs: Dict[str, deque] = defaultdict(deque)
    
    def allow_request(self, client_id: str) -> bool:
        """
        Check if a request is allowed for the given client.
        
        :param client_id: Unique identifier for the client
        :return: True if the request is allowed, False otherwise
        """
        current_time = time.time()
        client_log = self.request_logs[client_id]
        # Remove timestamps outside the current window
        while client_log and current_time - client_log[0] > self.window_size:
            client_log.popleft()
        # Check if the number of requests is within the limit
        if len(client_log) < self.max_requests:
            client_log.append(current_time)
            return True
        return False


# Initialize rate limiter
rate_limiter = SlidingWindowLog(window_size=WINDOW_SIZE, max_requests=MAX_REQUESTS)


# API key header for client identification
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# Dependency to get client ID from API key
async def get_client_id(api_key: str = Depends(api_key_header)):
    if not api_key:
        raise HTTPException(status_code=401, detail="API Key required")
    return api_key


# Example rate-limited endpoint
@app.get("/limited-endpoint")
async def limited_endpoint(client_id: str = Depends(get_client_id)):
    """
    A rate-limited endpoint that allows MAX_REQUESTS requests per WINDOW_SIZE seconds.
    """
    if rate_limiter.allow_request(client_id):
        return {"message": "Request allowed", "client_id": client_id}
    else:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {MAX_REQUESTS} requests per {WINDOW_SIZE} seconds"
        )


# Example unprotected endpoint for testing
@app.get("/unlimited-endpoint")
async def unlimited_endpoint():
    """
    An endpoint without rate limiting for comparison.
    """
    return {"message": "Request processed (no rate limit)"}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)