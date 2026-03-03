# 🔍**Suspected Data Exfiltration from PIPd Employee**

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/ab796c31-b368-4294-af03-cae6f68f4f3f" />


## Example Scenario:
An employee in a sensitive department was recently placed on a Performance Improvement Plan (PIP). Following an outburst, management is concerned he may attempt to exfiltrate proprietary data before resigning. Investigate his activity on the corporate device (danscenario3lab) using Microsoft Defender for Endpoint (MDE) to ensure no suspicious behavior is occurring.

NOTE: I spun up a VM on Azure, and then onboarded it to Microsoft Defender for Endpoint. This will act as the corporate device.

## Goal:
Because John is an administrator on his device and is not limited on which applications he uses, he may try to archive/compress sensitive information and send it to a private drive or something.
Identify if John has exfiltrated data from the corporate device.

---

### **Timeline Overview**  
I did a search within MDE DeviceFileEvents for any activities with .zip files, discovered regular activity of archiving files and moving to a “backup” folder.

   - **Detection Query:**
```kql
DeviceFileEvents
| where DeviceName == "danscenario3lab"
| where FileName endswith ".zip"
| order by Timestamp desc
```

## Sample Output:

<img width="1164" height="454" alt="Screenshot 2026-03-02 195455" src="https://github.com/user-attachments/assets/88c88613-c0d7-4983-9dcc-a112464e462a" />

---

### Silent Install Detection

I took one of the instances of a .zip file being created, took the timestamp and conducted a search under DeviceProcessEvents for events happening 2 minutes before the archive was created and 2 minutes after. I discovered around the same time, a powershell script silently installed 7zip and then used it to zip up employee data into an archive.

**Detection Query:**

```kql
let VMname = "danscenario3lab";
let specificTime = datetime(2026-02-28T00:18:18.2602054Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) ..(specificTime + 2m ))
| where DeviceName == VMname
| order by Timestamp desc
```

## Sample Output:

<img width="1190" height="679" alt="Screenshot 2026-03-02 201131" src="https://github.com/user-attachments/assets/329c9028-b244-4870-98ce-e156891f0a97" />


---

## Further Investigation

I searched around the same time period for any evidence of exfiltration from the network, but did not see any logs indicating such:


**Detection Query:**
```kql
let VMname = "danscenario3lab";
let specificTime = datetime(2026-02-28T00:18:18.2602054Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 2m) ..(specificTime + 2m ))
| where DeviceName == VMname
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType
```
*No Results from Query*

---

**Relevant TTPs(Tactics, Techniques, and Procedures):**

# 🛡️ MITRE ATT&CK TTPs for Incident Detection

| Tactic ID | Tactic Name        | TTP ID     | TTP Name                                      | Description                                                                 | Why It Applies Here |
|-----------|-------------------|------------|-----------------------------------------------|-----------------------------------------------------------------------------|---------------------|
| TA0002    | Execution         | T1059.001  | PowerShell                                    | Adversaries may abuse PowerShell for execution of malicious commands.      | PowerShell script silently installed 7zip and executed compression. |
| TA0011    | Command and Control | T1105    | Ingress Tool Transfer                         | Adversaries may transfer tools to a compromised system.                    | 7zip was installed via script to enable file compression. |
| TA0009    | Collection        | T1560.001  | Archive Collected Data: Archive via Utility   | Adversaries may compress data using utilities before exfiltration.         | Employee data was zipped using 7zip. |
| TA0009    | Collection        | T1074.001  | Data Staged: Local Data Staging               | Adversaries may stage collected data locally prior to exfiltration.        | Archive files were created and moved to a backup folder. |
| TA0005    | Defense Evasion   | T1027      | Obfuscated/Compressed Files and Information   | Adversaries may compress data to evade detection.                          | Compression can reduce detection visibility prior to exfiltration. |
| TA0010    | Exfiltration      | T1041      | Exfiltration Over C2 Channel (Investigated)   | Adversaries may exfiltrate data over C2 channels.                          | Network logs were reviewed; no evidence of exfiltration was found. |


---
**📝 Response:**

Security operations relayed information to the employee’s manager, including creation of archives via powershell script. No evidence was found of exfiltration, but further investigation of the employee is necessary.

Take preventative measures:
  - DLP solutions
  - Immediately isolated the system.
  - Create alerts for Zip file activity, silent installs

