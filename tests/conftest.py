import pytest

from aegis_core.store import reset_store


@pytest.fixture(autouse=True)
def _clean_store():
    reset_store()
    yield
    reset_store()
