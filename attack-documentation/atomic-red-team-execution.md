# Atomic Red Team Attack Execution

## Overview
Validated detection rules by simulating 7 MITRE ATT&CK techniques using Atomic Red Team.

**Execution Date:** Feb 20, 2026  
**Environment:** Windows 11 Pro (homelab.local domain)  
**Success Rate:** 71% (5 successful, 2 failed)

---

## Successful Attacks (5/7)

### T1055.001 - Process Injection via Mavinject
**Command:**
```powershell
Invoke-AtomicTest T1055.001 -TestNumbers 1
```
**Result:** ✅ SUCCESS  
**Detection Time:** 28 seconds  
**Evidence:** Kibana Event ID 1 - mavinject.exe spawned by powershell.exe

---

### T1036.003 - LSASS Process Masquerading
**Command:**
```powershell
Invoke-AtomicTest T1036.003 -TestNumbers 1
```
**Result:** ✅ SUCCESS  
**Detection Time:** <10 seconds  
**Evidence:** Kibana Event ID 11 - Fake lsass.exe created in C:\Windows\Temp\

---

### T1053.005 - Scheduled Task Persistence
**Command:**
```powershell
Invoke-AtomicTest T1053.005 -TestNumbers 1
```
**Result:** ✅ SUCCESS  
**Detection Time:** Immediate  
**Evidence:** Kibana Event ID 1 - schtasks.exe creating startup task

---

### T1082 - System Information Discovery
**Command:**
```powershell
Invoke-AtomicTest T1082 -TestNumbers 1
```
**Result:** ✅ SUCCESS  
**Detection Time:** <5 seconds  
**Evidence:** Kibana Event ID 1 - systeminfo.exe execution

---

### T1012 - Registry Query Discovery
**Command:**
```powershell
Invoke-AtomicTest T1012 -TestNumbers 1
```
**Result:** ✅ SUCCESS  
**Detection Time:** <5 seconds  
**Evidence:** 25 reg.exe query executions detected

---

## Failed/Blocked Attacks (2/7)

### T1003.001 - LSASS Credential Dumping
**Command:**
```powershell
Invoke-AtomicTest T1003.001 -TestNumbers 1
```
**Result:** ❌ ACCESS DENIED (Windows Defender blocked)  
**Note:** Attack attempt logged in Sysmon. Detection rule would work if successful.

---

### T1547.001 - Registry Run Key Persistence  
**Command:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1
```
**Result:** ✅ SUCCESS  
**Evidence:** Registry key created, captured in logs

---

## Key Takeaways

- 30-40% test failure rate is normal for Atomic Red Team
- Failed attacks still generate telemetry for detection validation
- 100% detection coverage achieved for successful attacks
- Average detection time: <60 seconds