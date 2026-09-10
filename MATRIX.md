# 検知ルールのマトリクス

ログごとの集計と、MITRE ATT&CK上の位置を掲載。技法全体の検知保証ではありません。

## ログ種別ごとの集計

|対象ログ|ルール数|対応技法数|
|---|---:|---:|
|Windows Event|25|19|
|FW|10|8|
|Proxy|20|9|
|DNS|7|5|
|**合計**|**62**|**36**|

技法数はサブ技法IDを含む重複なしの件数。複数戦術への掲載は重複計上しません。ルール一覧は[README](README.md)を参照。

## 技法 × ログ

|技法・サブ技法|Windows Event|FW|Proxy|DNS|
|---|---|---|---|---|
|[T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)|[WIN-013](rules/windows/WIN-013.md)|—|—|—|
|[T1003.006 DCSync](https://attack.mitre.org/techniques/T1003/006)|[WIN-022](rules/windows/WIN-022.md)|—|—|—|
|[T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)|—|—|—|[DNS-006](rules/dns/DNS-006.md)|
|[T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)|—|[FW-002](rules/fw/FW-002.md)|—|—|
|[T1021.006 Windows Remote Management](https://attack.mitre.org/techniques/T1021/006)|[WIN-025](rules/windows/WIN-025.md)|—|—|—|
|[T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)|—|—|[PROXY-012](rules/proxy/PROXY-012.md), [PROXY-013](rules/proxy/PROXY-013.md)|—|
|[T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)|—|[FW-001](rules/fw/FW-001.md), [FW-003](rules/fw/FW-003.md), [FW-004](rules/fw/FW-004.md)|—|—|
|[T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)|—|[FW-009](rules/fw/FW-009.md)|—|—|
|[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)|[WIN-005](rules/windows/WIN-005.md), [WIN-011](rules/windows/WIN-011.md), [WIN-012](rules/windows/WIN-012.md)|—|—|—|
|[T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)|[WIN-001](rules/windows/WIN-001.md), [WIN-018](rules/windows/WIN-018.md)|—|—|—|
|[T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)|—|—|[PROXY-008](rules/proxy/PROXY-008.md), [PROXY-011](rules/proxy/PROXY-011.md)|—|
|[T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004)|—|—|[PROXY-010](rules/proxy/PROXY-010.md)|[DNS-001](rules/dns/DNS-001.md), [DNS-003](rules/dns/DNS-003.md), [DNS-007](rules/dns/DNS-007.md)|
|[T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)|[WIN-004](rules/windows/WIN-004.md), [WIN-008](rules/windows/WIN-008.md), [WIN-009](rules/windows/WIN-009.md)|—|—|—|
|[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)|[WIN-014](rules/windows/WIN-014.md)|—|[PROXY-001](rules/proxy/PROXY-001.md), [PROXY-002](rules/proxy/PROXY-002.md), [PROXY-003](rules/proxy/PROXY-003.md), [PROXY-005](rules/proxy/PROXY-005.md), [PROXY-006](rules/proxy/PROXY-006.md), [PROXY-014](rules/proxy/PROXY-014.md), [PROXY-015](rules/proxy/PROXY-015.md)|—|
|[T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)|[WIN-003](rules/windows/WIN-003.md), [WIN-007](rules/windows/WIN-007.md)|—|—|—|
|[T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003)|[WIN-006](rules/windows/WIN-006.md)|—|—|—|
|[T1187 Forced Authentication](https://attack.mitre.org/techniques/T1187)|—|[FW-005](rules/fw/FW-005.md)|—|—|
|[T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)|—|[FW-006](rules/fw/FW-006.md)|[PROXY-017](rules/proxy/PROXY-017.md), [PROXY-018](rules/proxy/PROXY-018.md), [PROXY-019](rules/proxy/PROXY-019.md)|—|
|[T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197)|[WIN-017](rules/windows/WIN-017.md)|—|—|—|
|[T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005)|[WIN-016](rules/windows/WIN-016.md)|—|—|—|
|[T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010)|[WIN-015](rules/windows/WIN-015.md)|—|—|—|
|[T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)|[WIN-019](rules/windows/WIN-019.md)|—|—|—|
|[T1498.002 Reflection Amplification](https://attack.mitre.org/techniques/T1498/002)|—|—|—|[DNS-004](rules/dns/DNS-004.md)|
|[T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003)|[WIN-010](rules/windows/WIN-010.md)|—|—|—|
|[T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003)|[WIN-023](rules/windows/WIN-023.md)|—|—|—|
|[T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)|—|—|[PROXY-004](rules/proxy/PROXY-004.md)|—|
|[T1567.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004)|—|—|[PROXY-007](rules/proxy/PROXY-007.md)|—|
|[T1568.002 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)|—|—|—|[DNS-002](rules/dns/DNS-002.md)|
|[T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)|[WIN-024](rules/windows/WIN-024.md)|[FW-010](rules/fw/FW-010.md)|—|—|
|[T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571)|—|[FW-008](rules/fw/FW-008.md)|—|—|
|[T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572)|—|—|[PROXY-009](rules/proxy/PROXY-009.md)|—|
|[T1590.002 DNS](https://attack.mitre.org/techniques/T1590/002)|—|—|—|[DNS-005](rules/dns/DNS-005.md)|
|[T1595.003 Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003)|—|—|[PROXY-016](rules/proxy/PROXY-016.md), [PROXY-020](rules/proxy/PROXY-020.md)|—|
|[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)|[WIN-021](rules/windows/WIN-021.md)|—|—|—|
|[T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)|[WIN-002](rules/windows/WIN-002.md)|—|—|—|
|[T1686 Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686)|[WIN-020](rules/windows/WIN-020.md)|[FW-007](rules/fw/FW-007.md)|—|—|

## ATT&CK 戦術列 1〜8

|[TA0043 Reconnaissance](https://attack.mitre.org/tactics/TA0043)|[TA0042 Resource Development](https://attack.mitre.org/tactics/TA0042)|[TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001)|[TA0002 Execution](https://attack.mitre.org/tactics/TA0002)|[TA0003 Persistence](https://attack.mitre.org/tactics/TA0003)|[TA0004 Privilege Escalation](https://attack.mitre.org/tactics/TA0004)|[TA0005 Stealth](https://attack.mitre.org/tactics/TA0005)|[TA0112 Defense Impairment](https://attack.mitre.org/tactics/TA0112)|
|---|---|---|---|---|---|---|---|
|[T1590.002 DNS](https://attack.mitre.org/techniques/T1590/002)<br>[DNS-005](rules/dns/DNS-005.md)|—|[T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190)<br>[FW-006](rules/fw/FW-006.md), [PROXY-017](rules/proxy/PROXY-017.md), [PROXY-018](rules/proxy/PROXY-018.md), [PROXY-019](rules/proxy/PROXY-019.md)|[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/windows/WIN-005.md)（関連）, [WIN-011](rules/windows/WIN-011.md)（関連）, [WIN-012](rules/windows/WIN-012.md)（関連）|[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/windows/WIN-005.md), [WIN-011](rules/windows/WIN-011.md), [WIN-012](rules/windows/WIN-012.md)|[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/windows/WIN-005.md)（関連）, [WIN-011](rules/windows/WIN-011.md)（関連）, [WIN-012](rules/windows/WIN-012.md)（関連）|[T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197)<br>[WIN-017](rules/windows/WIN-017.md)|[T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685)<br>[WIN-021](rules/windows/WIN-021.md)|
|[T1595.003 Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003)<br>[PROXY-016](rules/proxy/PROXY-016.md), [PROXY-020](rules/proxy/PROXY-020.md)| | |[T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)<br>[WIN-001](rules/windows/WIN-001.md), [WIN-018](rules/windows/WIN-018.md)|[T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)<br>[WIN-004](rules/windows/WIN-004.md), [WIN-008](rules/windows/WIN-008.md), [WIN-009](rules/windows/WIN-009.md)|[T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)<br>[WIN-004](rules/windows/WIN-004.md)（関連）, [WIN-008](rules/windows/WIN-008.md)（関連）, [WIN-009](rules/windows/WIN-009.md)（関連）|[T1218.005 Mshta](https://attack.mitre.org/techniques/T1218/005)<br>[WIN-016](rules/windows/WIN-016.md)|[T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)<br>[WIN-002](rules/windows/WIN-002.md)|
| | | |[T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197)<br>[WIN-017](rules/windows/WIN-017.md)（関連）|[T1197 BITS Jobs](https://attack.mitre.org/techniques/T1197)<br>[WIN-017](rules/windows/WIN-017.md)（関連）|[T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003)<br>[WIN-010](rules/windows/WIN-010.md)（関連）|[T1218.010 Regsvr32](https://attack.mitre.org/techniques/T1218/010)<br>[WIN-015](rules/windows/WIN-015.md)|[T1686 Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1686)<br>[FW-007](rules/fw/FW-007.md), [WIN-020](rules/windows/WIN-020.md)|
| | | | |[T1543.003 Windows Service](https://attack.mitre.org/techniques/T1543/003)<br>[WIN-010](rules/windows/WIN-010.md)| | | |

## ATT&CK 戦術列 9〜15

|[TA0006 Credential Access](https://attack.mitre.org/tactics/TA0006)|[TA0007 Discovery](https://attack.mitre.org/tactics/TA0007)|[TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008)|[TA0009 Collection](https://attack.mitre.org/tactics/TA0009)|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|[TA0040 Impact](https://attack.mitre.org/tactics/TA0040)|
|---|---|---|---|---|---|---|
|[T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001)<br>[WIN-013](rules/windows/WIN-013.md)|[T1018 Remote System Discovery](https://attack.mitre.org/techniques/T1018)<br>[DNS-006](rules/dns/DNS-006.md)|[T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)<br>[FW-002](rules/fw/FW-002.md)|—|[T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001)<br>[PROXY-008](rules/proxy/PROXY-008.md), [PROXY-011](rules/proxy/PROXY-011.md)|[T1041 Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041)<br>[PROXY-012](rules/proxy/PROXY-012.md), [PROXY-013](rules/proxy/PROXY-013.md)|[T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490)<br>[WIN-019](rules/windows/WIN-019.md)|
|[T1003.006 DCSync](https://attack.mitre.org/techniques/T1003/006)<br>[WIN-022](rules/windows/WIN-022.md)|[T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)<br>[FW-001](rules/fw/FW-001.md), [FW-003](rules/fw/FW-003.md), [FW-004](rules/fw/FW-004.md)|[T1021.006 Windows Remote Management](https://attack.mitre.org/techniques/T1021/006)<br>[WIN-025](rules/windows/WIN-025.md)| |[T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004)<br>[DNS-001](rules/dns/DNS-001.md), [DNS-003](rules/dns/DNS-003.md), [DNS-007](rules/dns/DNS-007.md), [PROXY-010](rules/proxy/PROXY-010.md)|[T1048 Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)<br>[FW-009](rules/fw/FW-009.md)|[T1498.002 Reflection Amplification](https://attack.mitre.org/techniques/T1498/002)<br>[DNS-004](rules/dns/DNS-004.md)|
|[T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)<br>[WIN-003](rules/windows/WIN-003.md), [WIN-007](rules/windows/WIN-007.md)| |[T1570 Lateral Tool Transfer](https://attack.mitre.org/techniques/T1570)<br>[FW-010](rules/fw/FW-010.md), [WIN-024](rules/windows/WIN-024.md)| |[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br>[PROXY-001](rules/proxy/PROXY-001.md), [PROXY-002](rules/proxy/PROXY-002.md), [PROXY-003](rules/proxy/PROXY-003.md), [PROXY-005](rules/proxy/PROXY-005.md), [PROXY-006](rules/proxy/PROXY-006.md), [PROXY-014](rules/proxy/PROXY-014.md), [PROXY-015](rules/proxy/PROXY-015.md), [WIN-014](rules/windows/WIN-014.md)|[T1567.002 Exfiltration to Cloud Storage](https://attack.mitre.org/techniques/T1567/002)<br>[PROXY-004](rules/proxy/PROXY-004.md)| |
|[T1110.003 Password Spraying](https://attack.mitre.org/techniques/T1110/003)<br>[WIN-006](rules/windows/WIN-006.md)| | | |[T1568.002 Domain Generation Algorithms](https://attack.mitre.org/techniques/T1568/002)<br>[DNS-002](rules/dns/DNS-002.md)|[T1567.004 Exfiltration Over Webhook](https://attack.mitre.org/techniques/T1567/004)<br>[PROXY-007](rules/proxy/PROXY-007.md)| |
|[T1187 Forced Authentication](https://attack.mitre.org/techniques/T1187)<br>[FW-005](rules/fw/FW-005.md)| | | |[T1571 Non-Standard Port](https://attack.mitre.org/techniques/T1571)<br>[FW-008](rules/fw/FW-008.md)| | |
|[T1558.003 Kerberoasting](https://attack.mitre.org/techniques/T1558/003)<br>[WIN-023](rules/windows/WIN-023.md)| | | |[T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572)<br>[PROXY-009](rules/proxy/PROXY-009.md)| | |

「関連」は公式の所属戦術。ルール単独で各戦術の目的達成を証明するものではありません。親技法は各ルールに記載。

[MITRE公式STIX](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack.json)：戦術順と技法の所属を参照（確認2026-09-10）。
