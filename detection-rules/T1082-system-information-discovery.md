# Detection Rule: System Information Discovery

## MITRE ATT&CK
- **Technique ID:** T1082
- **Technique Name:** System Information Discovery
- **Tactic:** Discovery
- **Severity:** Low-Medium

## Description
Detects execution of systeminfo.exe, a Windows utility that displays detailed configuration information about a computer and its operating system. Attackers routinely use this command early in the attack lifecycle to understand the environment they've compromised, identify security controls, and determine appropriate exploitation techniques.

## Technical Background
Systeminfo.exe is a built-in Windows command-line utility that provides comprehensive system information including OS version, hardware specifications, installed hotfixes, network configuration, and domain membership. While legitimate IT administrators use this tool for troubleshooting and inventory, it's extremely rare in normal user workflows. Attackers use systeminfo.exe to:
- Identify OS version for exploit selection
- Check for security patches/hotfixes
- Determine if running in a VM or sandbox
- Understand hardware capabilities
- Identify antivirus or EDR products

## Detection Logic

### KQL Query (Kibana)
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "systeminfo.exe"
```

### Enhanced Detection (Focus on Suspicious Context)
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "systeminfo.exe" AND
(process.parent.name: ("powershell.exe" OR "cmd.exe" OR "wscript.exe") OR
 user.name: (*$ OR "NETWORK SERVICE" OR "LOCAL SERVICE"))
```

### Key Detection Fields
| Field | Value in Attack | Why It Matters |
|-------|----------------|----------------|
| `event.code` | 1 | Process Creation event |
| `process.name` | systeminfo.exe | Discovery utility |
| `process.parent.name` | cmd.exe | Launched from command line |
| `user.name` | Administrator | User context |

## Test Case - Atomic Red Team

### Execution Command
```powershell
Invoke-AtomicTest T1082 -TestNumbers 1
```

### Expected Behavior
1. Test executes systeminfo.exe
2. Command dumps complete system configuration to console
3. Sysmon Event ID 1 captures process creation
4. Detection rule triggers immediately
5. Output includes OS version, patches, domain info, etc.

### Lab Test Results
- **Environment:** Windows 11 Pro (homelab.local)
- **User Context:** Administrator
- **Detection Time:** Immediate (<5 seconds)
- **Execution Date:** Feb 20, 2026 @ 14:30:20
- **Parent Process:** cmd.exe
- **Evidence:** Systeminfo execution captured in Sysmon logs

## False Positives

### Known Legitimate Uses
1. **IT Support & Helpdesk**
   - Troubleshooting user issues
   - Hardware inventory collection
   - System health checks
   - **Frequency:** Rare (only during active troubleshooting)

2. **System Management Tools**
   - SCCM/Intune inventory collection
   - Asset management software
   - Remote monitoring tools
   - **Frequency:** Scheduled (predictable)

3. **Automated Scripts**
   - Deployment validation scripts
   - Health check automation
   - Compliance scanning
   - **Frequency:** Scheduled and predictable

### Expected False Positive Rate
**5-10% in typical environments**  
**Higher in environments with active IT support**

## Tuning Recommendations

### Level 1 - Whitelist Known Management Tools
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "systeminfo.exe" AND
NOT process.parent.name: ("sccm_client.exe" OR "ManagementAgent.exe")
```

### Level 2 - Alert on User Context Execution
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "systeminfo.exe" AND
NOT user.name: ("NT AUTHORITY\\SYSTEM" OR "SCCM_SERVICE_ACCOUNT")
```

### Level 3 - Correlation with Other Discovery Commands
Alert if systeminfo.exe + multiple other discovery tools within 5 minutes:
```kql
(process.name: "systeminfo.exe" OR 
 process.name: "ipconfig.exe" OR 
 process.name: "whoami.exe" OR 
 process.name: "net.exe")
```

Multiple discovery commands in quick succession = likely reconnaissance phase.

### Level 4 - Time-Based Filtering
Suppress during known maintenance windows:
```kql
event.module: sysmon AND 
event.code: 1 AND 
process.name: "systeminfo.exe" AND
NOT @timestamp: [maintenance_window_start TO maintenance_window_end]
```

## Investigation Playbook

### Immediate Actions (0-5 minutes)
1. **Context Assessment**
   - Who executed it? (user.name)
   - From where? (process.parent.name)
   - When? (timestamp)
   - Is this user known to run system commands?

2. **Pattern Recognition**
   - Single execution or part of a series?
   - Check for other discovery commands nearby (whoami, ipconfig, net user)
   - Review user's recent command history

### Containment (5-15 minutes)
3. **Determine Legitimacy**
   - **Legitimate:** IT helpdesk ticket, scheduled scan, management tool
   - **Suspicious:** No helpdesk ticket, unknown user, after-hours execution
   - **Critical:** Combined with other recon tools, from external IP, compromised account

4. **Escalation Decision**
   - If part of broader reconnaissance → Escalate immediately
   - If isolated + legitimate context → Document and close
   - If uncertain → Continue investigation

### Investigation (15+ minutes)
5. **Broader Analysis**
   - Review all commands executed by this user in last hour
   - Check for file downloads or lateral movement
   - Examine network connections from this endpoint
   - Search for similar activity on other systems

6. **Threat Hunting**
   - Look for credential dumping attempts (T1003)
   - Check for privilege escalation (T1068)
   - Review persistence mechanisms (T1053, T1547)
   - Examine lateral movement indicators (T1021)

## Remediation Steps

### Immediate
1. If malicious: Isolate endpoint from network
2. Terminate any suspicious processes
3. Force password reset for affected user
4. Preserve logs and memory dump
5. Document timeline of reconnaissance activity

### Short-term
6. Review and harden affected account permissions
7. Check for unauthorized access or data exfiltration
8. Search other endpoints for same user activity
9. Update EDR signatures if new malware identified
10. Brief IT staff on incident details

### Long-term
11. Implement application whitelisting for recon tools
12. Deploy honeytokens/canary files to detect enumeration
13. Enable enhanced command-line logging
14. Restrict systeminfo.exe via AppLocker for standard users
15. Security awareness training on social engineering

## Prevention Recommendations

### Technical Controls
**AppLocker Restrictions:**
```powershell
# Block systeminfo.exe for standard users
# Allow only for approved admin groups and service accounts
```

**PowerShell Logging:**
```
Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root
Set-ItemProperty -Path HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging -Name EnableScriptBlockLogging -Value 1
```

**Command Line Auditing:**
```
Computer Configuration → Administrative Templates → 
System → Audit Process Creation → 
Include command line in process creation events: Enabled
```

**Least Privilege:**
- Remove unnecessary admin rights
- Implement LAPS for local admin passwords
- Use just-in-time privileged access

### Detective Controls
- Real-time SIEM alerting (this rule)
- EDR behavioral detection
- Correlation with other discovery techniques
- User behavior analytics (UBA)

## Real-World Context

### Threat Actor Usage
- **Universal Technique:** Used by virtually all threat actors
- **APT Groups:** APT28, APT29, Lazarus, Wizard Spider (all use systeminfo)
- **Malware:** Emotet, TrickBot, Cobalt Strike, Metasploit (all include systeminfo)
- **Ransomware:** Pre-deployment reconnaissance phase

### Industry Impact
- Found in 80%+ of penetration test reports
- Standard step in automated attack frameworks
- Included in red team playbooks worldwide
- First command executed after initial access in many incidents

### Attack Chain Position
Systeminfo typically appears:
- **Early:** Minutes to hours after initial compromise
- **Discovery Phase:** Part of broader reconnaissance
- **Before Lateral Movement:** Understanding environment before spreading
- **Multiple Times:** Re-run when moving to new systems

## MITRE ATT&CK Mapping

**Primary Technique:** T1082 - System Information Discovery

**Related Techniques:**
- T1016 - System Network Configuration Discovery
- T1033 - System Owner/User Discovery
- T1007 - System Service Discovery
- T1518.001 - Security Software Discovery

**Kill Chain Phase:** Discovery

**Common Follow-on Techniques:**
- T1087 - Account Discovery
- T1069 - Permission Groups Discovery
- T1083 - File and Directory Discovery
- T1057 - Process Discovery

## References
- [MITRE ATT&CK T1082](https://attack.mitre.org/techniques/T1082/)
- [Microsoft Docs - Systeminfo](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/systeminfo)
- [Atomic Red Team T1082](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md)
- [Sysmon Event ID 1](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SANS - Windows Discovery Techniques](https://www.sans.org/white-papers/)

## Version History
- v1.0 - Initial rule creation and validation via Atomic Red Team testing
- Detection validated: Feb 20, 2026
- Lab environment: Windows 11 Pro + ELK Stack 9.2.4

## Author
Adam Takeuchi - SOC Detection Lab Project