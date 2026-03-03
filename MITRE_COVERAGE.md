# MITRE ATT&CK Coverage

This document describes how the SOC platform maps alerts and detection rules to the MITRE ATT&CK framework.

## Detection rules and techniques

Detection rules in `app/core/detection_rules/rules/` are designed to map to MITRE ATT&CK techniques where applicable. Use this file to track coverage and gaps.

| Rule / Use Case | MITRE Technique(s) | Notes |
|-----------------|--------------------|--------|
| brute_force     | T1110 (Brute Force) | |
| lateral_movement | T1021.002, T1570 | |
| privilege_escalation | T1068, T1548, etc. | |
| data_exfiltration | T1041, T1048 | |
| persistence | T1547, T1053, etc. | |
| credential_dumping | T1003 | |
| port_scan | T1046 | |
| suspicious_account | T1136, T1098 | |

## Mapping and enrichment

- `app/core/mitre/` provides technique mapping and lookup.
- Alerts and incidents can be enriched with MITRE technique IDs for reporting and dashboards.

## Extending coverage

1. Add or update YAML rules under `app/core/detection_rules/rules/`.
2. Reference technique IDs in rule metadata.
3. Update this table and run tests to validate mappings.
