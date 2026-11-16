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


def test_the_host_services_are_governed_by_the_input_hook() -> None:
    """The mirror and the apt proxy bind the job's own gateway.

    That address is the host's address on the bridge, so a packet to it is
    delivered locally and never reaches the forward hook. A locked phase that
    only replaced the forward chain would close nothing: the provisioning
    channel would stay open for the life of the job.
    """
    rules = provisioning_rules(apt_port=8082)
    assert "chain input {" in rules
    inputs = rules.split("chain input {")[1]
    assert "ip daddr 10.42.0.1 tcp dport 8081 accept" in inputs
    assert "ip daddr 10.42.0.1 tcp dport 8082 accept" in inputs
    assert 'iifname "xentry0" drop' in inputs


def test_the_locked_phase_closes_the_host_services() -> None:
    rules = locked_rules([3100])
    inputs = rules.split("chain input {")[1]
    assert "8081" not in inputs
    assert "8082" not in inputs
    assert "udp dport 67 accept" in inputs
    assert "udp dport 53 accept" in inputs
    assert 'iifname "xentry0" drop' in inputs


def test_the_input_chain_cannot_lock_the_operator_out() -> None:
    """A base chain's policy applies to every packet that reaches its hook.

    policy drop on input would drop ssh to the host itself, not just guest
    traffic. The scoping is per rule, with a final drop on the job bridge.
    """
    for rules in (provisioning_rules(apt_port=8082), locked_rules([80])):
        inputs = rules.split("chain input {")[1]
        assert "type filter hook input priority 0; policy accept;" in inputs
        # Every rule names the bridge, so nothing off it is touched.
        for line in inputs.splitlines():
            body = line.strip()
            if not body or body in {"}", "}}"} or body.startswith("type filter"):
                continue
            assert body.startswith('iifname "xentry0"'), body


def test_the_broker_keeps_its_ssh_sessions_through_a_phase_change() -> None:
    # The broker reaches a guest over ssh from the host; the guest's replies
    # arrive on the input hook. Without this rule a phase change kills every
    # open session and the harness stops being able to drive its own VMs.
    for rules in (provisioning_rules(), locked_rules([80])):
        inputs = rules.split("chain input {")[1]
        assert 'iifname "xentry0" ct state established,related accept' in inputs
