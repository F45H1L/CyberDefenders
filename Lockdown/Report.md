# Lockdown - Report

## Digital Forensics & Malware Incident Investigation Report

**Investigation Type:** Network Forensics, Memory Forensics & Malware Analysis  
**Platform:** CyberDefenders  
**Target System:** Windows IIS Server  
**Operating System:** Windows 10 / Server build 17763  
**Analysis Environment:** Kali Linux  
**Status:** Completed

---

# 1. Executive Summary

This report documents the forensic investigation of a compromised Windows IIS server using network traffic analysis, memory forensics, static malware analysis, and threat intelligence.

The investigation revealed that the attacker performed network reconnaissance against the IIS server, accessed SMB shares, and uploaded an ASP.NET webshell named `shell.aspx`.

Following the webshell upload, the attacker established a reverse-shell connection over TCP port `4443`. Memory analysis revealed suspicious process activity involving the IIS worker process (`w3wp.exe`), which spawned a malicious executable named `updatenow.exe`.

The executable was found in the Windows Startup directory, indicating a possible persistence mechanism. Static analysis identified UPX as the packer used to obfuscate the executable. Threat-intelligence research associated its SHA-256 hash with the AgentTesla malware family and identified `cp8nl.hyperhost.ua` as its command-and-control (C2) domain.

The investigation successfully reconstructed the major stages of the intrusion and identified relevant indicators of compromise.

# 2. Investigation Objectives

The primary objectives were:

1. Identify the source IP address responsible for reconnaissance.
2. Determine the HTTP enumeration tool used by the attacker.
3. Identify SMB shares accessed during the intrusion.
4. Locate the uploaded webshell.
5. Identify the reverse-shell listener port.
6. Extract the Windows kernel base address from memory.
7. Identify the suspicious executable and its full path.
8. Correlate network activity with the responsible process.
9. Identify the packer used to obfuscate the malware.
10. Determine the command-and-control domain.
11. Attribute the malicious sample to its malware family.

# 3. Tools and Technologies

| Tool | Purpose |
|---|---|
| Wireshark | PCAP inspection and network traffic analysis |
| Volatility 3 | Windows memory forensics |
| UPX | Packer identification and executable unpacking |
| strings | Static string extraction |
| sha256sum | Malware hash calculation |
| MalwareBazaar | Malware sample identification and threat intelligence |
| ANY.RUN | Sandbox-based malware analysis |
| Kali Linux | Investigation environment |

# 4. Evidence Overview

The investigation used two primary forensic artifacts:

| Evidence | Description |
|---|---|
| PCAP file | Captured network traffic associated with the intrusion |
| `memdump.mem` | Memory image of the compromised Windows system |
| `updatenow.exe` | Suspicious executable recovered for static malware analysis |

The network capture was analyzed first to understand the attack activity. The memory image was then examined to identify suspicious processes, executable paths, and network connections.

# 5. Network Forensics

## 5.1 Reconnaissance Activity

The PCAP was opened in Wireshark to identify suspicious HTTP requests.

The following display filter was used:

```wireshark
http.request
```

A suspicious request was identified:

```text
/nmaplowercheck1725947084
```

Packet details:

| Field | Value |
|---|---|
| Packet Number | 2140 |
| Source IP | `10.0.2.4` |
| Destination IP | `10.0.2.15` |
| User-Agent | Nmap Scripting Engine |

The HTTP User-Agent contained:

```text
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
```

This confirms that the attacker used the Nmap Scripting Engine for HTTP enumeration.

**Finding:**

- Attacker IP: `10.0.2.4`
- Target IIS server: `10.0.2.15`
- Enumeration tool: Nmap Scripting Engine (NSE)

## 5.2 SMB Share Enumeration

SMB traffic was inspected to identify shared resources accessed by the attacker.

Wireshark display filter:

```wireshark
smb2.cmd == 3
```

Two SMB2 Tree Connect requests were identified.

**Packet 2672:**

```text
\\10.0.2.15\IPC$
```

**Packet 2678:**

```text
\\10.0.2.15\Documents
```

These requests demonstrate that the attacker accessed the IPC$ and Documents shares on the target server.

**Finding:**

The two accessed UNC paths were:

```text
\\10.0.2.15\IPC$
\\10.0.2.15\Documents
```

## 5.3 Webshell Upload

Further inspection of SMB2 file-write activity revealed the transfer of a suspicious ASP.NET file.

Wireshark display filter:

```wireshark
smb2.cmd == 9
```

Relevant packet:

| Field | Value |
|---|---|
| Packet Number | 3505 |
| Source IP | `10.0.2.4` |
| Destination IP | `10.0.2.15` |
| Operation | SMB2 Write Request |
| Filename | `shell.aspx` |

The file `shell.aspx` was transferred from the attacker system to the IIS server.

An ASP.NET webshell can provide an attacker with remote command execution through a web application.

**Finding:**

Uploaded webshell:

```text
shell.aspx
```

## 5.4 Reverse-Shell Connection

The network capture was examined for outbound TCP connections originating from the compromised IIS server.

Display filter:

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

A suspicious TCP connection was identified.

Relevant packet:

| Field | Value |
|---|---|
| Packet Number | 3585 |
| Source IP | `10.0.2.15` |
| Source Port | `49688` |
| Destination IP | `10.0.2.4` |
| Destination Port | `4443` |

The connection originated from the IIS server and targeted port `4443` on the attacker system.

This activity is consistent with a reverse-shell connection.

**Finding:**

Reverse-shell listener port:

```text
4443
```

# 6. Memory Forensics

## 6.1 Operating System and Kernel Information

Volatility 3 was used to examine the Windows memory image.

Command:

```bash
vol -f memdump.mem windows.info
```

The plugin extracted Windows operating-system and kernel information.

Relevant findings:

| Field | Value |
|---|---|
| Operating System | Windows |
| Build | 17763 |
| Architecture | 64-bit |
| Kernel Base | `0xf80079213000` |
| System Time | 2024-09-10 06:14:13 UTC |

**Finding:**

Windows kernel base address:

```text
0xf80079213000
```

## 6.2 Process Enumeration

The running and recently terminated processes were examined using:

```bash
vol -f memdump.mem windows.pslist
```

The following process relationships were identified:

| PID | PPID | Process Name |
|---:|---:|---|
| 2452 | 628 | `svchost.exe` |
| 4332 | 2452 | `w3wp.exe` |
| 900 | 4332 | `updatenow.exe` |

The process `w3wp.exe` is the IIS worker process responsible for handling web application requests.

The suspicious executable `updatenow.exe` was observed as a child process of `w3wp.exe`.

This parent-child relationship is significant because it connects the compromised IIS worker process with the execution of the implanted executable.

## 6.3 Suspicious Executable Identification

The command line associated with PID `900` was examined using:

```bash
vol -f memdump.mem windows.cmdline --pid 900
```

The recovered command-line path was:

```text
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe
```

The executable was located in the Windows Startup directory.

Programs placed in this directory may execute automatically when a user logs in, making it a potential persistence location.

**Finding:**

Suspicious executable:

```text
updatenow.exe
```

Full path:

```text
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe
```

PID:

```text
900
```

Parent PID:

```text
4332
```

## 6.4 Network Connection and Process Correlation

The memory image was examined for network connections using:

```bash
vol -f memdump.mem windows.netscan
```

To narrow the results:

```bash
vol -f memdump.mem windows.netscan | grep 4443
```

The network activity was correlated with the process tree and the reverse-shell connection identified in the PCAP.

The relevant process was:

```text
w3wp.exe
```

PID:

```text
4332
```

The process hierarchy was:

```text
svchost.exe (PID 2452)
        |
        v
w3wp.exe (PID 4332)
        |
        v
updatenow.exe (PID 900)
```

This correlation indicates that the IIS worker process handled the reverse-shell activity and spawned the suspicious executable.

**Finding:**

Process responsible for the reverse-shell activity and spawning the implanted executable:

```text
w3wp.exe (PID 4332)
```

# 7. Malware Static Analysis

## 7.1 Sample Identification

The suspicious executable recovered during the investigation was identified as:

```text
updatenow.exe
```

Its SHA-256 hash was calculated using:

```bash
sha256sum updatenow.exe
```

Hash:

```text
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f
```

This hash was used to identify the sample through external threat-intelligence sources.

## 7.2 Packer Identification

The executable was initially inspected using the `strings` utility.

Command:

```bash
strings updatenow.exe
```

The following strings were identified:

```text
UPX0
UPX1
.rsrc
UPX!
```

The presence of `UPX0`, `UPX1`, and the `UPX!` signature indicated that the executable was packed using UPX.

The identification was verified with:

```bash
upx -t updatenow.exe
```

Output:

```text
testing updatenow.exe [OK]
Tested 1 file.
```

The executable was then unpacked:

```bash
upx -d updatenow.exe -o updatenow_unpacked.exe
```

The unpacking operation completed successfully.

**Finding:**

Packer:

```text
UPX
```

## 7.3 Command-and-Control Domain Identification

The unpacked executable was inspected for readable strings and possible network indicators.

Command:

```bash
strings -a updatenow_unpacked.exe | grep -Ei 'https?://|[a-zA-Z0-9.-]+\.(com|net|org|ru|io|biz|info)'
```

Additional inspection:

```bash
strings -a updatenow_unpacked.exe | grep -Ei 'http|ftp|socket|connect|\.com|\.net|\.org'
```

The output showed network-related Windows API imports, including:

```text
HttpQueryInfoW
HttpOpenRequestW
HttpSendRequestW
InternetConnectW
FtpOpenFileW
```

However, the C2 domain was not directly exposed by these basic string searches.

The SHA-256 hash was therefore used for further threat-intelligence investigation.

The sample was researched using malware-analysis and threat-intelligence services, including MalwareBazaar and ANY.RUN.

The identified C2 domain was:

```text
cp8nl.hyperhost.ua
```

**Finding:**

Command-and-control FQDN:

```text
cp8nl.hyperhost.ua
```

## 7.4 Malware Family Attribution

The SHA-256 hash was submitted to MalwareBazaar and cross-referenced with sandbox analysis.

Sample hash:

```text
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f
```

The sample was associated with the AgentTesla malware family.

AgentTesla is a commodity remote access trojan and information stealer commonly associated with credential theft and data exfiltration.

**Finding:**

Malware family:

```text
AgentTesla
```

# 8. Attack Timeline

The following timeline reconstructs the major activities observed during the investigation.

| Stage | Activity | Evidence |
|---|---|---|
| 1 | HTTP reconnaissance | Nmap NSE request from `10.0.2.4` |
| 2 | SMB share access | `IPC$` and `Documents` Tree Connect requests |
| 3 | Webshell transfer | `shell.aspx` uploaded to the IIS server |
| 4 | Reverse-shell connection | TCP connection to port `4443` |
| 5 | Suspicious process execution | `w3wp.exe` spawned `updatenow.exe` |
| 6 | Potential persistence | Executable located in Startup directory |
| 7 | Malware identification | UPX-packed executable |
| 8 | Threat-intelligence attribution | AgentTesla and `cp8nl.hyperhost.ua` |

The process creation timestamps from memory included:

| Process | PID | Creation Time (UTC) |
|---|---:|---|
| `w3wp.exe` | 4332 | 2024-09-10 05:44:45 |
| `updatenow.exe` | 900 | 2024-09-10 06:08:23 |

The `w3wp.exe` process was recorded as exiting at `06:10:48 UTC`.

These timestamps provide additional context for the suspicious process activity.

# 9. Indicators of Compromise (IOCs)

The following indicators were identified during the investigation.

## 9.1 Network Indicators

| Indicator | Value |
|---|---|
| Attacker IP Address | `10.0.2.4` |
| Compromised IIS Server | `10.0.2.15` |
| Reverse-Shell Destination Port | `4443` |
| C2 Domain | `cp8nl.hyperhost.ua` |

## 9.2 File Indicators

| Indicator | Value |
|---|---|
| Uploaded Webshell | `shell.aspx` |
| Malicious Executable | `updatenow.exe` |
| Malware SHA-256 | `c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f` |
| Packer | UPX |
| Malware Family | AgentTesla |

## 9.3 Host Indicators

| Indicator | Value |
|---|---|
| Suspicious Process | `updatenow.exe` |
| Suspicious PID | `900` |
| Parent Process | `w3wp.exe` |
| Parent PID | `4332` |
| Executable Path | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |

# 10. MITRE ATT&CK Mapping

The observed activities can be mapped to the following MITRE ATT&CK techniques.

| Tactic | Technique | ID | Observed Evidence |
|---|---|---|---|
| Discovery | Network Service Discovery | T1046 | Nmap reconnaissance |
| Lateral Movement | SMB/Windows Admin Shares | T1021.002 | SMB share access |
| Initial Access / Execution | Exploitation of Public-Facing Application | T1190 | IIS webshell activity; exploitation mechanism not independently established |
| Persistence | Registry Run Keys / Startup Folder | T1547.001 | Executable stored in Startup directory |
| Execution | Command and Scripting Interpreter | T1059 | Webshell and reverse-shell activity; exact interpreter not established |
| Command and Control | Application Layer Protocol | T1071 | HTTP-related APIs and C2 attribution; protocol requires further traffic/configuration confirmation |

**Note:** These mappings are investigative interpretations, not proof that every technique was definitively executed. In particular, the precise initial access method and C2 protocol would require additional evidence.

# 11. Investigation Findings Summary

| Question | Finding |
|---|---|
| Q1 | `10.0.2.4` |
| Q2 | Nmap Scripting Engine (NSE) |
| Q3 | `\\10.0.2.15\IPC$` and `\\10.0.2.15\Documents` |
| Q4 | `shell.aspx` |
| Q5 | `4443` |
| Q6 | `0xf80079213000` |
| Q7 | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |
| Q8 | `w3wp.exe`, PID `4332` |
| Q9 | UPX |
| Q10 | `cp8nl.hyperhost.ua` |
| Q11 | AgentTesla |

# 12. Security Recommendations

Based on the observed intrusion activity, the following defensive measures are recommended.

### IIS and Web Application Security

- Remove unauthorized ASP.NET webshells and investigate all recently modified web application files.
- Restrict write permissions on IIS web directories.
- Run application pools with least-privilege service accounts.
- Review IIS logs for suspicious requests, unusual POST activity, and unexpected application execution.
- Keep IIS, Windows, and web application components patched.

### Network Security

- Restrict SMB access to trusted systems and networks.
- Block unnecessary outbound connections from IIS servers.
- Monitor unusual outbound TCP connections, especially connections to uncommon external ports.
- Deploy network detection rules for suspicious reverse-shell activity.
- Monitor DNS requests to suspicious domains.

### Endpoint Security

- Investigate suspicious child processes created by `w3wp.exe`.
- Monitor execution from Windows Startup directories.
- Deploy endpoint detection and response (EDR) solutions.
- Enable PowerShell, process creation, and relevant Windows security auditing.
- Perform a full investigation for additional persistence mechanisms and compromised credentials.

### Incident Response

- Isolate the affected IIS server from the network.
- Preserve memory images, PCAP files, system logs, and malware samples.
- Reset potentially compromised credentials after assessing the scope of the incident.
- Rebuild the server from a trusted image if system integrity cannot be established.
- Monitor for renewed connections to known malicious infrastructure.

# 13. Conclusion

The Lockdown Lab investigation demonstrated how an attacker compromised a Windows IIS server through a sequence of reconnaissance, SMB activity, webshell deployment, and reverse-shell communication.

Network forensics identified the attacker as `10.0.2.4` and revealed the uploaded webshell `shell.aspx`. The reverse-shell connection targeted TCP port `4443`.

Memory forensics identified the suspicious executable `updatenow.exe`, located in the Windows Startup directory. Process analysis linked its execution to the IIS worker process `w3wp.exe` (PID `4332`).

Static malware analysis revealed that the executable was packed with UPX. Threat-intelligence research associated its SHA-256 hash with AgentTesla and identified `cp8nl.hyperhost.ua` as its C2 domain.

By combining network forensics, memory analysis, static malware inspection, and threat intelligence, the investigation reconstructed the major stages of the compromise and identified actionable indicators of compromise.

---

## 14. References

- [CyberDefenders](https://cyberdefenders.org/)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Volatility 3 Documentation](https://volatility3.readthedocs.io/)
- [UPX Official Website](https://upx.github.io/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [ANY.RUN](https://any.run/)
- [VirusTotal](https://www.virustotal.com/)
- [MITRE ATT&CK](https://attack.mitre.org/)

**End of Report**