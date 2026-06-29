"""Tests for hackerone_public_recon - parsing + mapping (no live network)."""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "recon-osint" / "scripts"))

import hackerone_public_recon as h1  # noqa: E402

FIXTURE = {"data": {"team": {"handle": "acme", "structured_scopes": {"edges": [
    {"node": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD", "eligible_for_submission": True}},
    {"node": {"asset_identifier": "api.acme.com", "asset_type": "URL", "eligible_for_submission": True}},
    {"node": {"asset_identifier": "203.0.113.0/24", "asset_type": "CIDR", "eligible_for_submission": True}},
    {"node": {"asset_identifier": "legacy.acme.com", "asset_type": "URL", "eligible_for_submission": False}},
    {"node": {"asset_identifier": "com.acme.app", "asset_type": "GOOGLE_PLAY_APP_ID", "eligible_for_submission": True}},
    {"node": {"asset_identifier": "*.acme.com", "asset_type": "WILDCARD", "eligible_for_submission": True}},  # dupe
]}}}}


def test_parse_splits_in_out_and_filters_non_network():
    parsed = h1.parse_structured_scopes(FIXTURE)
    assert parsed["in_scope"] == ["*.acme.com", "api.acme.com", "203.0.113.0/24"]   # deduped, ordered
    assert parsed["out_of_scope"] == ["legacy.acme.com"]
    assert "com.acme.app" not in parsed["in_scope"]        # mobile app id is not a network target
    assert any(a["type"] == "GOOGLE_PLAY_APP_ID" for a in parsed["assets"])  # still recorded


def test_parse_handles_garbage():
    assert h1.parse_structured_scopes({})["in_scope"] == []
    assert h1.parse_structured_scopes({"data": {"team": None}})["out_of_scope"] == []


def test_to_candidate_scope_flags_authorization():
    parsed = h1.parse_structured_scopes(FIXTURE)
    cand = h1.to_candidate_scope(parsed, "acme")
    assert cand["in_scope"] == parsed["in_scope"]
    assert "CANDIDATE" in cand["engagement"]
    assert "REPLACE-ME" in cand["authorization_ref"]       # never silently treated as ROE


def test_graphql_query_shape():
    q = h1.graphql_query("acme")
    assert q["variables"]["handle"] == "acme" and "structured_scopes" in q["query"]


def test_fetch_scopes_with_injected_opener():
    class _Resp(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    def fake_opener(req, timeout=0):
        assert req.full_url == "https://hackerone.com/graphql"
        return _Resp(json.dumps(FIXTURE).encode())
    data = h1.fetch_scopes("acme", opener=fake_opener)
    assert h1.parse_structured_scopes(data)["in_scope"][0] == "*.acme.com"
