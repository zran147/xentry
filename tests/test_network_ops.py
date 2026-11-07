"""nftables rule generation tests."""

from __future__ import annotations

from broker.network_ops import locked_rules, provisioning_rules


def test_provisioning_allows_only_mirror_and_dhcp_dns() -> None:
    rules = provisioning_rules()
    assert "policy drop;" in rules
    assert 'ip daddr 10.42.0.1 tcp dport 8081 accept' in rules
    assert "udp dport 67 accept" in rules
    assert "udp dport 53 accept" in rules
    assert "10.42.0.20" not in rules
    assert "tcp dport 80 accept" not in rules


def test_locked_rules_allow_only_attacker_target_ports() -> None:
    rules = locked_rules([80, 443])
    assert "policy drop;" in rules
    assert "ip saddr 10.42.0.20 ip daddr 10.42.0.10 tcp dport { 80, 443 } accept" in rules
    assert "8081" not in rules
    assert "ip saddr 10.42.0.10 ip daddr 10.42.0.20" not in rules


def test_locked_rules_without_ports_has_no_guest_to_guest_accept() -> None:
    rules = locked_rules([])
    assert "10.42.0.20 ip daddr 10.42.0.10 tcp dport" not in rules
    assert "policy drop;" in rules
