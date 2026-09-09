# MITRE ATT&CK Matrix

公式の戦術列順に、ルールが対応する位置を掲載。技法全体の検知を意味するものではありません。

## 戦術列 1〜8

|[TA0043 Reconnaissance](https://attack.mitre.org/tactics/TA0043)|[TA0042 Resource Development](https://attack.mitre.org/tactics/TA0042)|[TA0001 Initial Access](https://attack.mitre.org/tactics/TA0001)|[TA0002 Execution](https://attack.mitre.org/tactics/TA0002)|[TA0003 Persistence](https://attack.mitre.org/tactics/TA0003)|[TA0004 Privilege Escalation](https://attack.mitre.org/tactics/TA0004)|[TA0005 Stealth](https://attack.mitre.org/tactics/TA0005)|[TA0112 Defense Impairment](https://attack.mitre.org/tactics/TA0112)|
|---|---|---|---|---|---|---|---|
|—|—|—|[T1059.001 PowerShell](https://attack.mitre.org/techniques/T1059/001)<br>[WIN-001](rules/windows/WIN-001.md)|[T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)<br>[WIN-004](rules/windows/WIN-004.md)|[T1098.007 Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007)<br>[WIN-004](rules/windows/WIN-004.md)（関連）|—|[T1685.005 Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005)<br>[WIN-002](rules/windows/WIN-002.md)|
| | | |[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/windows/WIN-005.md)（関連）|[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/windows/WIN-005.md)|[T1053.005 Scheduled Task](https://attack.mitre.org/techniques/T1053/005)<br>[WIN-005](rules/windows/WIN-005.md)（関連）| | |

## 戦術列 9〜15

|[TA0006 Credential Access](https://attack.mitre.org/tactics/TA0006)|[TA0007 Discovery](https://attack.mitre.org/tactics/TA0007)|[TA0008 Lateral Movement](https://attack.mitre.org/tactics/TA0008)|[TA0009 Collection](https://attack.mitre.org/tactics/TA0009)|[TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011)|[TA0010 Exfiltration](https://attack.mitre.org/tactics/TA0010)|[TA0040 Impact](https://attack.mitre.org/tactics/TA0040)|
|---|---|---|---|---|---|---|
|[T1110.001 Password Guessing](https://attack.mitre.org/techniques/T1110/001)<br>[WIN-003](rules/windows/WIN-003.md)|[T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046)<br>[FW-001](rules/fw/FW-001.md)|[T1021.001 Remote Desktop Protocol](https://attack.mitre.org/techniques/T1021/001)<br>[FW-002](rules/fw/FW-002.md)|—|[T1071.004 DNS](https://attack.mitre.org/techniques/T1071/004)<br>[NDR-001](rules/ndr/NDR-001.md)|—|—|
| | | | |[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br>[PROXY-001](rules/proxy/PROXY-001.md)| | |
| | | | |[T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105)<br>[PROXY-002](rules/proxy/PROXY-002.md)| | |

「関連」は公式の所属戦術で、実行や権限昇格の成立をルール単独で判断するものではありません。親技法とサブ技法は各ルールに記載。

[MITRE公式STIX](https://raw.githubusercontent.com/mitre-attack/attack-stix-data/6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack.json)：戦術順と技法の所属を参照（2026-09-09）。
