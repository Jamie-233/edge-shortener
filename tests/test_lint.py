from netlint.lint import lint


IOS_BAD = """
hostname sw1
!
enable password cisco123
snmp-server community public RO
snmp-server community private RW
!
vlan 10
 name DATA
vlan 20
 name VOICE
vlan 999
 name UNUSED
!
interface GigabitEthernet1/0/1
 switchport mode trunk
 switchport trunk allowed vlan 1,10,20
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
!
ip http server
!
line vty 0 4
 transport input telnet ssh
!
ntp server 10.0.0.1
"""

IOS_CLEAN = """
hostname sw1
!
enable secret 5 $1$abc$def
snmp-server community readonlystuff RO
!
vlan 10
 name DATA
!
interface GigabitEthernet1/0/1
 switchport mode trunk
 switchport trunk allowed vlan 10
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 10
!
ntp authenticate
ntp server 10.0.0.1
"""


def _rules(issues):
    return {i.rule for i in issues}


def test_bad_config_flags_issues():
    issues = lint(IOS_BAD)
    rules = _rules(issues)
    assert "plaintext-enable" in rules
    assert "snmp-community" in rules
    assert "trunk-vlan1" in rules
    assert "http-server" in rules
    assert "telnet-enabled" in rules
    assert "ntp-unauthenticated" in rules
    assert "unused-vlan" in rules  # vlan 20 and 999 never referenced


def test_clean_config_has_no_errors():
    issues = lint(IOS_CLEAN)
    assert all(i.severity == "warning" for i in issues) or not issues
    assert "plaintext-enable" not in _rules(issues)
    assert "snmp-community" not in _rules(issues)


def test_duplicate_address_detected():
    config = """
interface GigabitEthernet1/0/1
 ip address 10.0.0.1 255.255.255.0
!
interface GigabitEthernet1/0/2
 ip address 10.0.0.1 255.255.255.0
"""
    issues = lint(config)
    assert any(i.rule == "duplicate-address" for i in issues)


def test_vlan_batch_parsing():
    config = """
vlan batch 10 20 to 25
interface GigabitEthernet1/0/1
 port link-type trunk
 port trunk allow-pass vlan 10 20 to 25
"""
    issues = lint(config)
    assert not any(i.rule == "unused-vlan" for i in issues)
