# Tines SOAR Workflow Documentation

## Overview
Automated security orchestration workflow for alert processing and response.

**Platform:** Tines (Cloud-hosted SOAR)  
**Response Time:** <60 seconds end-to-end

---

## Workflow Components

### 1. Receive SIEM Alert (Webhook)
**Type:** Webhook Trigger  
**Method:** POST  
**Payload:**
```json
{
  "alert_name": "Process Injection Detected",
  "technique": "T1055.001",
  "severity": "High",
  "hostname": "LabWin11",
  "process_name": "mavinject.exe",
  "user": "Administrator"
}
```

---

### 2. Send Email Notification
**Template:**
```
🚨 Security Alert Detected

Alert: {{alert_name}}
Severity: {{severity}}
MITRE ATT&CK: {{technique}}

System: {{hostname}}
User: {{user}}
Process: {{process_name}}

Investigate immediately.
```

---

### 3. VirusTotal Threat Intelligence
**API:** VirusTotal v3  
**Method:** GET file hash reputation  
**Purpose:** Determine if process is known malware

---

### 4. Case Logging
**Storage:** Tines Event Store  
**Purpose:** Audit trail and investigation tracking

---

## Triggering Method

**Lab Environment:** Manual webhook trigger via curl  
**Production:** Kibana alerting would auto-trigger on detection

**Manual Trigger Example:**
```bash
curl -X POST "https://tines-webhook-url" \
  -H "Content-Type: application/json" \
  -d '{"alert_name":"Process Injection Detected",...}'
```

---

## Results

**Time Savings:**
- Manual triage: 15-30 minutes
- Automated response: <60 seconds
- Improvement: 95%+
```

---