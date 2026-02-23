# Detection Rule: Query Registry for Discovery

## MITRE ATT&CK
- **Technique ID:** T1012
- **Technique Name:** Query Registry
- **Tactic:** Discovery
- **Severity:** Low-Medium

## Description
Detects execution of reg.exe with the "query" parameter, indicating registry enumeration activity. Attackers query the Windows registry to discover system configuration, installed software (especially security products), network settings, and potential credentials. This technique is commonly used during the reconnaissance phase to understand the compromised environment.

## Technical Background
The Windows Registry is a hierarchical database that stores configuration settings and options for the operating system, applications, and users. The reg.exe command-line utility allows reading and modifying registry keys. While legitimate administrators use reg.exe for troubleshooting and configuration, it's uncommon in normal user workflows. Attackers query the registry to:
- Enumerate installed security software (antivirus, EDR)
- Identify installed patches and hotfixes (vulnerability assessment)
- Locate stored credentials in registry keys
- Discover network configuration and domain information
- Find AutoRun locations for persistence opportunities

## Detection Logic

### KQL Query (Kibana)
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "reg.exe" AND 
process.command_line: *query*
```

### Enhanced Detection (Focus on Sensitive Keys)
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "reg.exe" AND 
process.command_line: *query* AND
(process.command_line: (*Software\\Microsoft\\Windows\\CurrentVersion\\Run* OR
                        *SYSTEM\\CurrentControlSet\\Services* OR
                        *Security\\Policy\\Secrets* OR
                        *SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon* OR
                        *Control\\HotPatch*))
```

### Key Detection Fields
| Field | Value in Attack | Why It Matters |
|-------|----------------|----------------|
| `event.code` | 1 | Process Creation event |
| `process.name` | reg.exe | Registry manipulation utility |
| `process.command_line` | reg query "HKEY_LOCAL_MACHINE\..." | Full command with specific key |
| `process.parent.name` | cmd.exe | What launched reg.exe |
| `user.name` | SYSTEM | User context |

## Test Case - Atomic Red Team

### Execution Command
```powershell
Invoke-AtomicTest T1012 -TestNumbers 1
```

### Expected Behavior
1. Test executes multiple reg.exe query commands
2. Queries various registry keys for system information
3. Example: Queries HotPatch key to identify installed updates
4. Sysmon Event ID 1 captures each reg.exe execution
5. Detection rule triggers for each query

### Lab Test Results
- **Environment:** Windows 11 Pro (homelab.local)
- **User Context:** SYSTEM
- **Detection Time:** Immediate (<5 seconds)
- **Execution Date:** Feb 20, 2026 @ 14:45:19
- **Query Count:** 25 registry queries detected
- **Example Query:** `reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\HotPatch"`
- **Evidence:** Multiple Sysmon events capturing registry enumeration

## False Positives

### Known Legitimate Uses
1. **IT Administration & Troubleshooting**
   - System configuration checks
   - Software installation verification
   - Registry cleanup/optimization
   - **Frequency:** Occasional (during active support)

2. **System Management Tools**
   - SCCM/Intune configuration validation
   - Group Policy troubleshooting
   - Monitoring/inventory software
   - **Frequency:** Scheduled and predictable

3. **Software Installation & Updates**
   - Application installers checking registry
   - Update tools verifying configurations
   - Compatibility checks
   - **Frequency:** During software deployment

4. **Backup & Recovery**
   - System backup software
   - Disaster recovery tools
   - Registry backup utilities
   - **Frequency:** Scheduled

### Expected False Positive Rate
**10-15% without tuning**  
**<5% after environment-specific tuning**

## Tuning Recommendations

### Level 1 - Whitelist Management Tools
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "reg.exe" AND 
process.command_line: *query* AND
NOT process.parent.name: ("sccm_client.exe" OR "ManagementAgent.exe" OR "BackupExec.exe")
```

### Level 2 - Focus on High-Value Keys
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "reg.exe" AND 
process.command_line: (*Run* OR *RunOnce* OR *Winlogon* OR *Services* OR *Policy\\Secrets*)
```

### Level 3 - Alert on User Context Queries
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "reg.exe" AND 
process.command_line: *query* AND
NOT user.name: ("NT AUTHORITY\\SYSTEM" OR "NETWORK SERVICE")
```

### Level 4 - Correlation with Other Discovery
Alert if reg.exe query + other discovery commands within 5 minutes:
```kql
(process.name: "reg.exe" AND process.command_line: *query*) OR
(process.name: "systeminfo.exe") OR
(process.name: "whoami.exe") OR
(process.name: "net.exe")
```

Multiple discovery tools = active reconnaissance phase.

## Investigation Playbook

### Immediate Actions (0-5 minutes)
1. **Identify Target Keys**
   - Which registry keys were queried?
   - **Critical Keys:** RunKeys, Winlogon, Services, Policy\Secrets
   - **Moderate Keys:** Software lists, network config
   - **Low Risk:** System info, patch status

2. **Context Analysis**
   - Who executed it? (user context)
   - Parent process? (scripted vs. interactive)
   - Time of day? (business hours vs. after-hours)
   - Single query or multiple rapid queries?

### Containment (5-15 minutes)
3. **Assess Threat Level**
   - **Critical:** Queries to credential storage, RunKeys, Services
   - **High:** Multiple sensitive keys, unusual user context
   - **Medium:** Patch/software enumeration, known recon pattern
   - **Low:** Single query, legitimate admin context

4. **Determine Next Steps**
   - If part of attack chain → Isolate endpoint immediately
   - If suspicious → Continue monitoring, preserve logs
   - If legitimate → Document and whitelist source

### Investigation (15+ minutes)
5. **Broader Analysis**
   - Review all commands from this user/session
   - Check for privilege escalation attempts
   - Look for lateral movement indicators
   - Search for credential dumping (often follows registry queries)
   - Examine network connections for C2 activity

6. **Threat Hunting**
   - Search other endpoints for same registry queries
   - Review similar activity from this user account
   - Check for new scheduled tasks or services (persistence)
   - Look for unauthorized registry modifications

## Remediation Steps

### Immediate
1. If malicious: Isolate affected endpoint
2. Terminate suspicious processes
3. Review queried registry keys for modifications
4. Check for new persistence mechanisms
5. Force password reset if credential keys accessed

### Short-term
6. Remove any unauthorized registry modifications
7. Delete malicious scheduled tasks/services if created
8. Audit all admin account activity
9. Search for lateral movement from affected system
10. Document IOCs (registry keys queried, command patterns)

### Long-term
11. Implement registry monitoring/auditing
12. Restrict reg.exe execution via AppLocker
13. Deploy honeytokens in registry (canary keys)
14. Enable enhanced command-line logging
15. Security awareness training on reconnaissance techniques

## Prevention Recommendations

### Technical Controls
**AppLocker Restrictions:**
```powershell
# Block reg.exe for standard users
# Allow only for approved admin groups and service accounts
New-AppLockerPolicy -RuleType Publisher -Path * -Publisher "O=Microsoft Corporation*"
```

**Registry Auditing:**
```
Computer Configuration → Windows Settings → Security Settings → 
Advanced Audit Policy Configuration → Object Access → 
Audit Registry: Success and Failure
```

**PowerShell Constrained Language Mode:**
```powershell
# Prevent PowerShell from calling reg.exe
[Environment]::SetEnvironmentVariable("__PSLockdownPolicy","4","Machine")
```

**Least Privilege:**
- Remove unnecessary admin rights
- Implement LAPS for local admin passwords
- Use just-in-time privileged access
- Restrict registry read permissions on sensitive keys

### Detective Controls
- Real-time SIEM alerting (this rule)
- Registry honeytokens/canary keys
- Correlation with other discovery techniques
- User behavior analytics (UBA)
- EDR behavioral monitoring

## Real-World Context

### Threat Actor Usage
- **Universal Technique:** Used by virtually all post-exploitation frameworks
- **APT Groups:** APT28, APT29, Lazarus, Wizard Spider
- **Frameworks:** Metasploit, Cobalt Strike, Empire, PoshC2
- **Malware:** TrickBot, Emotet, Qakbot (automated registry recon)

### Industry Impact
- Found in 70%+ of penetration test reports
- Standard step in automated attack frameworks
- Included in all major red team playbooks
- Commonly used for AV/EDR detection evasion

### Attack Chain Position
Registry queries typically appear:
- **Early Discovery:** Minutes after initial compromise
- **Pre-Persistence:** Before establishing scheduled tasks/services
- **Pre-Privilege Escalation:** Identifying unpatched vulnerabilities
- **Pre-Credential Dumping:** Locating stored credentials

### Common Query Targets
**Security Software Detection:**
- `HKLM\SOFTWARE\Microsoft\Windows Defender`
- `HKLM\SOFTWARE\Symantec`
- `HKLM\SYSTEM\CurrentControlSet\Services\WinDefend`

**Persistence Locations:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\SYSTEM\CurrentControlSet\Services`

**Credential Storage:**
- `HKLM\SECURITY\Policy\Secrets`
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

## MITRE ATT&CK Mapping

**Primary Technique:** T1012 - Query Registry

**Related Techniques:**
- T1082 - System Information Discovery
- T1518.001 - Security Software Discovery
- T1552.002 - Credentials in Registry
- T1547.001 - Registry Run Keys (Persistence)

**Kill Chain Phase:** Discovery

**Common Follow-on Techniques:**
- T1003 - Credential Dumping
- T1547 - Boot or Logon Autostart Execution
- T1078 - Valid Accounts
- T1543.003 - Windows Service

## References
- [MITRE ATT&CK T1012](https://attack.mitre.org/techniques/T1012/)
- [Microsoft Docs - Reg Command](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg)
- [Atomic Red Team T1012](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1012/T1012.md)
- [Sysmon Event ID 1](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SANS - Windows Registry Forensics](https://www.sans.org/white-papers/)

## Version History
- v1.0 - Initial rule creation and validation via Atomic Red Team testing
- Detection validated: Feb 20, 2026
- Lab environment: Windows 11 Pro + ELK Stack 9.2.4

## Author
Adam Takeuchi - SOC Detection Lab Project