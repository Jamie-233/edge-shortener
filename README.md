# netlint

Lint Cisco IOS and Huawei VRP configs for common security and hygiene mistakes. Feed it a device config, get a list of problems with exit codes you can gate CI on.

## Install

```bash
pip install -e .
```

## Use

```bash
netlint switch1.cfg switch2.cfg
```

```
switch1.cfg: 3 error(s), 2 warning(s)
  [ERROR] plaintext-enable: enable password 'cisco123' is stored in plaintext; use 'enable secret'
  [ERROR] snmp-community: SNMP community 'public' is a default value and should not be used
  [WARNING] trunk-vlan1: trunk carries VLAN 1; use a dedicated unused native VLAN and prune VLAN 1 from trunks
```

Exit code is 1 when there are errors, or when warnings exceed `--max-warnings` (default 0), so it drops into CI as a check step.

## Checks

- plaintext `enable password` (should be `enable secret`)
- default SNMP communities (`public` / `private`)
- trunk carrying VLAN 1
- telnet allowed on vty lines
- plaintext `ip http server`
- NTP servers without `ntp authenticate`
- duplicate IP addresses across interfaces
- VLANs defined but never referenced by any port

Not supported (yet): VRP-specific `display current-configuration` output with `#` section markers, `interface` blocks with sub-interface names, and IPv6 addressing.

## Dev

```bash
pip install -e '.[dev]'
pytest
```
