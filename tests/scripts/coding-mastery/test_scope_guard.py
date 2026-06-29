"""Adversarial tests for scope_guard — the guard must err SAFE.

Run: pytest tests/scripts/coding-mastery/test_scope_guard.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "skills" / "coding-mastery" / "scripts" / "_lib"))

import pytest  # noqa: E402
import scope_guard as sg  # noqa: E402


def make_scope(**kw):
    data = {"engagement": "test", "in_scope": kw.get("in_scope", ["acme.com"])}
    if "out_of_scope" in kw:
        data["out_of_scope"] = kw["out_of_scope"]
    if "max_cidr_hosts" in kw:
        data["max_cidr_hosts"] = kw["max_cidr_hosts"]
    return sg.Scope(data)


# --------------------------------------------------------- classify
@pytest.mark.parametrize("value,kind", [
    ("acme.com", "domain"),
    ("*.acme.com", "wildcard"),
    ("203.0.113.0/24", "cidr"),
    ("198.51.100.7", "ip"),
    ("2001:db8::/32", "cidr"),
    ("https://api.acme.com/v1", "url"),
    ("not a host", "invalid"),
    ("*.com", "invalid"),         # bare TLD wildcard is nonsense
    ("", "invalid"),
])
def test_classify(value, kind):
    assert sg.classify(value) == kind


# --------------------------------------------------------- wildcard look-alike rejection (CORE)
def test_wildcard_rejects_lookalikes():
    s = make_scope(in_scope=["*.acme.com"])
    assert s.evaluate("evil-acme.com").in_scope is False        # prefix look-alike
    assert s.evaluate("acme.com.evil.com").in_scope is False    # suffix-graft
    assert s.evaluate("notacme.com").in_scope is False
    assert s.evaluate("acme.com.attacker.net").in_scope is False
    assert s.evaluate("xacme.com").in_scope is False


def test_wildcard_matches_real_subdomains():
    s = make_scope(in_scope=["*.acme.com"])
    assert s.evaluate("api.acme.com").in_scope is True
    assert s.evaluate("a.b.c.acme.com").in_scope is True


def test_wildcard_does_not_match_apex():
    s = make_scope(in_scope=["*.acme.com"])
    assert s.evaluate("acme.com").in_scope is False             # apex must be listed separately


def test_apex_listed_separately():
    s = make_scope(in_scope=["acme.com", "*.acme.com"])
    assert s.evaluate("acme.com").in_scope is True
    assert s.evaluate("api.acme.com").in_scope is True


# --------------------------------------------------------- exact domain
def test_exact_domain_no_substring_match():
    s = make_scope(in_scope=["acme.com"])
    assert s.evaluate("acme.com").in_scope is True
    assert s.evaluate("api.acme.com").in_scope is False         # not a wildcard
    assert s.evaluate("aacme.com").in_scope is False


# --------------------------------------------------------- out-of-scope precedence
def test_out_of_scope_wins():
    s = make_scope(in_scope=["*.acme.com"], out_of_scope=["dev.acme.com"])
    assert s.evaluate("dev.acme.com").in_scope is False
    assert s.evaluate("prod.acme.com").in_scope is True


def test_out_of_scope_wildcard():
    s = make_scope(in_scope=["*.acme.com"], out_of_scope=["*.internal.acme.com"])
    assert s.evaluate("db.internal.acme.com").in_scope is False
    assert s.evaluate("www.acme.com").in_scope is True


# --------------------------------------------------------- IPs / CIDR
def test_cidr_membership():
    s = make_scope(in_scope=["203.0.113.0/24"])
    assert s.evaluate("203.0.113.45").in_scope is True
    assert s.evaluate("203.0.114.1").in_scope is False


def test_ip_exact():
    s = make_scope(in_scope=["198.51.100.7"])
    assert s.evaluate("198.51.100.7").in_scope is True
    assert s.evaluate("198.51.100.8").in_scope is False


def test_ipv6_cidr():
    s = make_scope(in_scope=["2001:db8::/32"])
    assert s.evaluate("2001:db8::1").in_scope is True
    assert s.evaluate("[2001:db8::1]:443").in_scope is True
    assert s.evaluate("2001:dead::1").in_scope is False


def test_ip_not_matched_by_domain_rule():
    s = make_scope(in_scope=["acme.com"])
    assert s.evaluate("203.0.113.1").in_scope is False


def test_domain_not_matched_by_cidr_rule():
    s = make_scope(in_scope=["203.0.113.0/24"])
    assert s.evaluate("acme.com").in_scope is False


# --------------------------------------------------------- normalization
def test_case_insensitive():
    s = make_scope(in_scope=["*.acme.com"])
    assert s.evaluate("API.ACME.COM").in_scope is True


def test_trailing_dot():
    s = make_scope(in_scope=["acme.com"])
    assert s.evaluate("acme.com.").in_scope is True


def test_port_stripped_for_host_match():
    s = make_scope(in_scope=["*.acme.com"])
    assert s.evaluate("api.acme.com:8443").in_scope is True


def test_url_target_host_extracted():
    s = make_scope(in_scope=["*.acme.com"])
    assert s.evaluate("https://api.acme.com/login?x=1").in_scope is True
    assert s.evaluate("https://evil.com/?next=api.acme.com").in_scope is False


def test_url_rule_matches_host():
    s = make_scope(in_scope=["https://api.acme.com"])
    assert s.evaluate("api.acme.com").in_scope is True
    assert s.evaluate("other.acme.com").in_scope is False


# --------------------------------------------------------- default-deny & validation
def test_default_deny():
    s = make_scope(in_scope=["acme.com"])
    assert s.evaluate("unrelated.org").in_scope is False


def test_empty_in_scope_rejected():
    with pytest.raises(sg.ScopeError):
        sg.Scope({"engagement": "x", "in_scope": []})


def test_invalid_rule_rejected():
    with pytest.raises(sg.ScopeError):
        sg.Scope({"in_scope": ["acme.com", "not a host !!"]})


# --------------------------------------------------------- CIDR expansion cap
def test_expand_cidr_caps():
    with pytest.raises(sg.ScopeError):
        sg.expand_cidr("10.0.0.0/8", max_hosts=254)


def test_expand_cidr_small_ok():
    hosts = sg.expand_cidr("203.0.113.0/29", max_hosts=254)
    assert "203.0.113.1" in hosts and len(hosts) <= 6


# --------------------------------------------------------- CLI contract
def test_cli_check_exit_codes(tmp_path, capsys):
    sf = tmp_path / "scope.json"
    sf.write_text('{"engagement":"t","in_scope":["*.acme.com"]}', encoding="utf-8")
    assert sg.main(["check", "api.acme.com", "--scope", str(sf)]) == 0
    assert sg.main(["check", "evil-acme.com", "--scope", str(sf)]) == 3
    assert sg.main(["check", "x", "--scope", str(tmp_path / "missing.json")]) == 2


def test_cli_classify(capsys):
    assert sg.main(["classify", "*.acme.com"]) == 0
    assert sg.main(["classify", "not a host"]) == 2
