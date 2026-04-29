# Rapport de conversion Sigma → SIEM

Total règles : **5**

| Règle | Splunk SPL | Sentinel KQL |
|-------|-----------|--------------|
| `dns_beaconing/sigma_rule.yml` — DNS Beaconing - Suspicious Repetitive TXT/NULL Queries (Sysmon EID 22) | OK | N/A |
| `lsass_process_access/sigma_rule.yml` — Suspicious LSASS Process Access (Sysmon EID 10) | OK | N/A |
| `mimikatz_lsass_dump/sigma_rule.yml` — Mimikatz / LSASS Dump — Suspicious Memory Access to lsass.exe | OK | N/A |
| `rdp_bruteforce/sigma_rule.yml` — RDP Brute Force - High Volume of Failed Logons Followed by Success | OK | N/A |
| `scheduled_task_persistence/sigma_rule.yml` — Scheduled Task Persistence - Suspicious Task Creation (EID 4698) | OK | N/A |