import pytest

from aegis_core.config import get_settings
from aegis_core.store import reset_store

TEST_API_KEY = "dev-aegis-api-key"
API_KEY_HEADERS = {"X-API-Key": TEST_API_KEY}


@pytest.fixture(autouse=True)
def _clean_store():
    get_settings.cache_clear()
    reset_store()
    yield
    reset_store()
    get_settings.cache_clear()
