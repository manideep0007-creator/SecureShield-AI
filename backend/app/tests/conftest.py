import os
import pytest
from app.api.security import rate_limiter

# Set default API key for test environment
os.environ["API_KEY"] = "test-api-key"

@pytest.fixture(autouse=True)
def reset_rate_limiter_fixture():
    rate_limiter.reset()
    yield
    rate_limiter.reset()
