"""
TINY MONITOR — Opt-in Live TinyFish Integration Test
Sends a genuine HTTP request to https://api.search.tinyfish.ai only when a valid,
uncompromised TINYFISH_API_KEY is configured in the local environment.
Never prints or leaks credentials.
"""

import pytest
from app.config import Config
from app.services.tinyfish_service import TinyFishService


@pytest.mark.live
def test_live_tinyfish_search_api():
    """
    Opt-in live integration test.
    Automatically skipped if TINYFISH_API_KEY is not configured or if an old compromised key is detected.
    """
    if not TinyFishService.is_configured():
        redacted = Config.get_redacted_api_key()
        pytest.skip(
            f"Opt-in Live TinyFish test skipped: Credential status is '{redacted}'. "
            "To run live tests, supply a newly rotated key in your local .env (TINYFISH_API_KEY)."
        )

    # Perform real search against live TinyFish Search API
    test_query = "Presidency University Bengaluru cybersecurity"
    test_purpose = "Tiny Monitor Live Hackathon Integration Test"

    res = TinyFishService.search(
        query=test_query,
        purpose=test_purpose,
        domain_type="web",
        timeout=15.0
    )

    # Verify genuine response shape
    assert "query" in res
    assert "results" in res
    assert "total_results" in res
    assert isinstance(res["results"], list)

    # Verify results structure if items returned
    if res["results"]:
        first = res["results"][0]
        assert "title" in first
        assert "url" in first
        assert "snippet" in first
        assert first["url"].startswith("http://") or first["url"].startswith("https://")
        assert len(first["title"]) > 0


@pytest.mark.live
def test_live_tinyfish_python_sdk():
    """
    Test live connectivity using the official TinyFish Python SDK client.
    Verifies that the SDK initializes from TINYFISH_API_KEY environment variable
    and successfully queries search and wallet endpoints without exposing credentials.
    """
    try:
        from tinyfish import TinyFish
    except ImportError:
        pytest.skip("tinyfish Python SDK is not installed.")

    import os
    if not os.environ.get("TINYFISH_API_KEY"):
        pytest.skip("TINYFISH_API_KEY is not set in environment.")

    client = TinyFish()
    # Test SDK Search query
    res = client.search.query(query="cisa.gov", purpose="Python SDK live test")
    assert res is not None
    assert hasattr(res, "results")
    assert isinstance(res.results, list)

    # Test SDK Wallet query
    wallet = client.wallet.get()
    assert wallet is not None
    assert hasattr(wallet, "currency")
    assert hasattr(wallet, "available_balance")

