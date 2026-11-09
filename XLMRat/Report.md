# XLMRat Malware Analysis Report

## 1. Executive Summary

This report documents the analysis of an XLMRat malware sample investigated through network traffic analysis, payload extraction, static analysis, and PowerShell script deobfuscation.

The investigation identified malicious HTTP communication, two embedded PE payloads, an AsyncRAT family detection, reflective loading through a legitimate Windows utility, and persistence through a scheduled task.

The analysis was performed in a controlled malware-analysis environment without intentionally executing the extracted malware.

---

## 2. Investigation Overview

| Category | Details |
|---|---|
| Lab | CyberDefenders - XLMRat |
| Malware Family | AsyncRAT |
| Initial Analysis | Wireshark |
| Payload Extraction | Python |
| File Analysis | ExifTool, VirusTotal |
| Script Analysis | PowerShell deobfuscation |
| Persistence Mechanism | Windows Scheduled Task |
| Analysis Type | Static and Network Analysis |

---

## 3. Network Traffic Analysis

### 3.1 Initial Download URL

Wireshark analysis identified the following HTTP request:

```text
http://45.126.209.4:222/xlm.txt
```

The response contained an obfuscated PowerShell script responsible for retrieving the next-stage payload.

### 3.2 Additional Download Request

The script initiated another HTTP request:

```text
http://45.126.209.4:222/mdm.jpg
```

Although the filename suggested an image, the downloaded content was identified as a text-based PowerShell script.

### 3.3 Command-and-Control / Hosting Infrastructure

| Attribute | Value |
|---|---|
| IP Address | 45.126.209.4 |
| Port | 222 |
| Protocol | HTTP |
| Initial Resource | `/xlm.txt` |
| Secondary Resource | `/mdm.jpg` |
| Hosting Provider | Pending investigation |

---

## 4. Malware Payload Analysis

### 4.1 Extracted Payloads

Two executable payloads were extracted from the malicious PowerShell script using Python-based hexadecimal decoding.

| File | Size | SHA256 |
|---|---:|---|
| loader_pe.exe | 76,288 bytes | `2c6c4cd045537e2586eab73072d790af362e37e6d4112b1d01f15574491296b8` |
| secondary.exe | 66,560 bytes | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |

Both files contained the expected `MZ` signature associated with Windows Portable Executable files.

### 4.2 Malware Identification

VirusTotal analysis of the secondary executable returned the following detection:

```text
Backdoor:MSIL/AsyncRat.a2786761
```

Another antivirus detection identified the sample as:

```text
Malware/Win.Generic.C4980844
```

These detections indicate that the secondary executable is associated with the AsyncRAT malware family.

---

## 5. PE Timestamp Analysis

ExifTool was used to inspect the PE metadata of `secondary.exe`.

| Attribute | Value |
|---|---|
| File | secondary.exe |
| PE Timestamp | 2023-10-30 15:08:44 UTC |
| Local Timestamp | 2023-10-30 20:38:44 UTC |
| Timezone | UTC+05:30 |

The PE timestamp represents the compilation timestamp recorded in the executable's metadata. It should not be confused with the filesystem modification timestamp.

Note that PE timestamps can be manipulated and should not be treated as definitive evidence of malware creation time.

---

## 6. Execution Mechanism Analysis

### 6.1 PowerShell Loader

The extracted PowerShell script contained obfuscated variables and string fragments.

The script reconstructed commands responsible for:

- Loading the extracted PE payload into memory.
- Dynamically loading a .NET assembly.
- Retrieving a method named `Execute`.
- Passing arguments to the reflective loader.
- Invoking a legitimate Windows utility as part of the execution chain.

### 6.2 Living-off-the-Land Binary

The script reconstructed the following executable path:

```text
C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe
```

`RegSvcs.exe` is a legitimate Microsoft .NET utility.

Its use in this context is associated with proxy execution, allowing malicious code to execute through a trusted Windows binary.

### 6.3 Reflective Code Loading

The script used .NET reflection to dynamically load an assembly and invoke its execution method.

This technique allows code to be loaded and executed in memory rather than relying exclusively on conventional executable launching.

---

## 7. Persistence Mechanism

### 7.1 Dropped Files

The malicious script created the following files inside:

```text
C:\Users\Public\
```

| Filename | Description |
|---|---|
| Conted.ps1 | PowerShell loader script |
| Conted.bat | Batch launcher for PowerShell |
| Conted.vbs | VBScript launcher for the batch file |

### 7.2 Scheduled Task

The script created a scheduled task using the Windows Task Scheduler COM interface.

| Attribute | Value |
|---|---|
| Task Name | Update Edge |
| Action | `C:\Users\Public\Conted.vbs` |
| Trigger | Repeating time trigger |
| Repeat Interval | 2 minutes |

The task was configured to execute the VBScript launcher repeatedly, providing a persistence mechanism.

---

## 8. MITRE ATT&CK Mapping

| Technique | ID | Evidence |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Obfuscated PowerShell loader |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | VBScript launcher |
| System Binary Proxy Execution: Regsvcs | T1218.009 | RegSvcs.exe invocation |
| Scheduled Task/Job | T1053 | Update Edge scheduled task |
| Reflective Code Loading | T1620 | .NET reflection and assembly loading |

These mappings are based on the behavior identified in the analyzed script. They should not automatically be interpreted as proof of successful execution on a victim endpoint.

---

## 9. Indicators of Compromise

### Network Indicators

```text
45.126.209.4
http://45.126.209.4:222/xlm.txt
http://45.126.209.4:222/mdm.jpg
```

### File Indicators

| File | SHA256 |
|---|---|
| loader_pe.exe | `2c6c4cd045537e2586eab73072d790af362e37e6d4112b1d01f15574491296b8` |
| secondary.exe | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |

### Host Indicators

```text
C:\Users\Public\Conted.ps1
C:\Users\Public\Conted.bat
C:\Users\Public\Conted.vbs
```

### Persistence Indicator

```text
Scheduled Task: Update Edge
```

---

## 10. Defensive Recommendations

1. Block identified malicious IP addresses and associated URLs where appropriate.
2. Monitor suspicious outbound HTTP requests from endpoints.
3. Investigate unexpected PowerShell execution with hidden windows or execution-policy bypasses.
4. Monitor suspicious execution of `RegSvcs.exe`.
5. Audit scheduled tasks for unexpected or frequently repeating execution triggers.
6. Investigate suspicious scripts and executables in `C:\Users\Public\`.
7. Enable PowerShell Script Block Logging and process creation auditing.
8. Use endpoint detection and response solutions to identify reflective code loading and suspicious .NET behavior.
9. Review network telemetry for additional communication with the identified infrastructure.
10. Perform containment and remediation if the identified indicators are discovered on an affected system.

---

## 11. Conclusion

The investigation identified a multi-stage malware delivery chain involving an obfuscated PowerShell downloader, embedded executable payloads, reflective .NET loading, and scheduled-task persistence.

The secondary executable was identified by VirusTotal as belonging to the AsyncRAT malware family.

The observed techniques demonstrate how malware can combine scripting, legitimate Windows utilities, and scheduled tasks to facilitate execution and persistence.

This investigation highlights the importance of network traffic analysis, static malware inspection, script deobfuscation, and host-based monitoring in identifying malicious activity.

---

## 12. References

- CyberDefenders: XLMRat Lab
- Wireshark
- VirusTotal
- ExifTool
- Microsoft Windows Task Scheduler
- MITRE ATT&CK Framework