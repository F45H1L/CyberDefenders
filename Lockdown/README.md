# Lockdown

## Overview

This write-up documents the investigation of a compromised Windows IIS server using **Wireshark**, **Volatility 3**, and malware-analysis tools.

The investigation covers:

- Network reconnaissance and enumeration
- SMB share access and webshell upload
- Reverse shell identification
- Memory forensics and process analysis
- Malware packing identification
- Threat-intelligence research and malware attribution

## Tools Used

- Wireshark
- Volatility 3
- Kali Linux
- UPX
- `strings`
- `sha256sum`
- MalwareBazaar
- ANY.RUN

---

# Part 1: Network Traffic Analysis (Q1–Q5)

Open the provided PCAP file in Wireshark.

```bash
wireshark lockdown.pcap
```

You can also use `tshark` for command-line packet analysis.

### Q1. What is the source IP address responsible for reconnaissance?

**Step 1:** Open the PCAP in Wireshark.

**Step 2:** Apply the HTTP display filter:

```wireshark
http.request
```

**Step 3:** Look for suspicious HTTP requests containing Nmap-related paths, such as:

```text
/nmaplowercheck1725947084
```

**Step 4:** Inspect the source and destination IP addresses.

Evidence:

- Packet: `2140`
- Source IP: `10.0.2.4`
- Destination IP: `10.0.2.15`
- User-Agent: `Nmap Scripting Engine`

**Answer:**

```text
10.0.2.4
```

### Q2. Which tool was used for HTTP enumeration?

**Step 1:** Select the suspicious HTTP request identified in Q1.

**Step 2:** Expand the HTTP section in the Packet Details pane.

**Step 3:** Inspect the `User-Agent` header.

Evidence:

```text
Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)
```

The User-Agent explicitly identifies the Nmap Scripting Engine.

**Answer:**

```text
Nmap Scripting Engine (NSE)
```

### Q3. What are the two SMB share paths accessed by the attacker?

**Step 1:** Apply the SMB2 Tree Connect Request filter:

```wireshark
smb2.cmd == 3
```

**Step 2:** Inspect the SMB2 Tree Connect Request packets.

**Step 3:** Expand the SMB2 section and locate the Tree field to identify the requested UNC paths.

Evidence:

Packet `2672`:

```text
\\10.0.2.15\IPC$
```

Packet `2678`:

```text
\\10.0.2.15\Documents
```

**Answer:**

```text
\\10.0.2.15\IPC$
\\10.0.2.15\Documents
```

### Q4. What was the filename of the uploaded webshell?

**Step 1:** Inspect SMB2 file-write requests.

Apply the filter:

```wireshark
smb2.cmd == 9
```

**Step 2:** Look for suspicious file-write activity and inspect the SMB2 filename field.

Evidence:

- Packet: `3505`
- Source: `10.0.2.4`
- Destination: `10.0.2.15`
- Operation: SMB2 Write Request
- Filename: `shell.aspx`

The file was uploaded to the compromised IIS server.

**Answer:**

```text
shell.aspx
```

### Q5. On which port was the reverse shell listener running?

**Step 1:** Look for outbound TCP connections from the compromised IIS server.

Apply the filter:

```wireshark
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Step 2:** Identify the connection from the IIS server (`10.0.2.15`) back to the attacker (`10.0.2.4`).

Evidence:

- Packet: `3585`
- Source: `10.0.2.15`
- Source port: `49688`
- Destination: `10.0.2.4`
- Destination port: `4443`

The destination port is the attacker's reverse-shell listener port.

To inspect the connection further:

```wireshark
tcp.port == 4443
```

**Answer:**

```text
4443
```

---

# Part 2: Memory Forensics (Q6–Q8)

Use Volatility 3 to investigate the supplied memory dump.

Navigate to the directory containing the memory image:

```bash
cd ~/Downloads/269-lockdown
```

### Q6. What is the kernel base address?

Run:

```bash
vol -f memdump.mem windows.info
```

This plugin retrieves Windows kernel and operating-system information from the memory image.

Inspect the `Kernel Base` field.

Evidence:

```text
Kernel Base: 0xf80079213000
```

**Answer:**

```text
0xf80079213000
```

### Q7. What is the full path of the suspicious executable?

**Step 1:** List running and recently terminated processes.

```bash
vol -f memdump.mem windows.pslist
```

Look for unusual processes and their parent-child relationships.

Relevant process entries:

| PID | PPID | Process |
|---:|---:|---|
| 2452 | 628 | svchost.exe |
| 4332 | 2452 | w3wp.exe |
| 900 | 4332 | updatenow.exe |

The process `updatenow.exe` is suspicious because it was spawned by the IIS worker process `w3wp.exe`.

**Step 2:** Inspect the command line of the suspicious process.

```bash
vol -f memdump.mem windows.cmdline --pid 900
```

Evidence:

```text
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe
```

The executable is located in the Windows Startup directory, suggesting persistence.

**Answer:**

```text
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe
```

### Q8. Which process handled the reverse-shell outbound traffic and spawned the implanted executable?

**Step 1:** Inspect network connections in memory.

```bash
vol -f memdump.mem windows.netscan
```

**Step 2:** Identify the connection associated with the reverse-shell port `4443` and attacker IP `10.0.2.4`.

You can narrow the output using:

```bash
vol -f memdump.mem windows.netscan | grep 4443
```

**Step 3:** Inspect the process name and PID associated with the connection.

Evidence:

```text
Process: w3wp.exe
PID: 4332
```

**Step 4:** Correlate the network connection with the process tree from Q7.

The process relationship is:

```text
svchost.exe (PID 2452)
        |
        v
w3wp.exe (PID 4332)
        |
        v
updatenow.exe (PID 900)
```

The IIS worker process `w3wp.exe` handled the reverse-shell connection and spawned the implanted executable.

**Answer:**

```text
w3wp.exe, 4332
```

---

# Part 3: Malware Sample Analysis (Q9–Q11)

The suspicious executable identified during memory analysis is:

```text
updatenow.exe
```

Navigate to the directory containing the extracted executable:

```bash
cd ~/Downloads/269-lockdown
```

### Q9. Which packer was used to obfuscate the executable?

**Step 1:** Calculate the executable's SHA-256 hash.

```bash
sha256sum updatenow.exe
```

Evidence:

```text
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f
```

**Step 2:** Inspect the executable's readable strings.

```bash
strings updatenow.exe
```

Look for suspicious section names and signatures.

Evidence:

```text
UPX0
UPX1
.rsrc
UPX!
```

These are characteristic UPX indicators.

**Step 3:** Verify the packer using UPX.

```bash
upx -t updatenow.exe
```

Expected result:

```text
testing updatenow.exe [OK]
Tested 1 file.
```

**Step 4:** Unpack the executable for further static analysis.

```bash
upx -d updatenow.exe -o updatenow_unpacked.exe
```

The executable is successfully unpacked.

**Answer:**

```text
UPX
```

### Q10. What is the fully qualified domain name (FQDN) of the command-and-control server?

The C2 domain may not appear in the original packed executable's readable strings.

**Step 1:** Search the unpacked executable for possible network indicators.

```bash
strings -a updatenow_unpacked.exe | grep -Ei 'https?://|\.com|\.net|\.org|\.ua'
```

**Step 2:** If the domain is not visible, use the SHA-256 hash from Q9 to investigate the sample using threat-intelligence sources.

Search for the hash:

```text
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f
```

Useful sources:

- [ANY.RUN – Sandbox Analysis](https://any.run/)
- [MalwareBazaar](https://bazaar.abuse.ch/)
- [VirusTotal](https://www.virustotal.com/)

**Step 3:** Inspect the sample's malware configuration, network activity, and DNS requests in the sandbox report.

The analysis identifies the C2 domain:

```text
cp8nl.hyperhost.ua
```

**Answer:**

```text
cp8nl.hyperhost.ua
```

### Q11. Which malware family does the sample belong to?

**Step 1:** Open MalwareBazaar and search for the SHA-256 hash:

```text
c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f
```

**Step 2:** Inspect the sample's classification and vendor detections.

The sample is identified as a variant of the AgentTesla malware family.

**Step 3:** Cross-check the classification with sandbox analysis.

The ANY.RUN report also identifies the sample as AgentTesla and provides its malware configuration, including the C2 host.

**Answer:**

```text
AgentTesla
```

---

# Final Answers (Q1–Q11)

| Question | Answer |
|---|---|
| Q1 | `10.0.2.4` |
| Q2 | Nmap Scripting Engine (NSE) |
| Q3 | `\\10.0.2.15\IPC$` and `\\10.0.2.15\Documents` |
| Q4 | `shell.aspx` |
| Q5 | `4443` |
| Q6 | `0xf80079213000` |
| Q7 | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |
| Q8 | `w3wp.exe`, PID `4332` |
| Q9 | `UPX` |
| Q10 | `cp8nl.hyperhost.ua` |
| Q11 | `AgentTesla` |

---

# Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| Attacker IP | `10.0.2.4` |
| Compromised IIS Server | `10.0.2.15` |
| Reverse Shell Port | `4443` |
| Uploaded Webshell | `shell.aspx` |
| Malicious Executable | `updatenow.exe` |
| Malware Path | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\updatenow.exe` |
| C2 Domain | `cp8nl.hyperhost.ua` |
| SHA-256 | `c25a6673a24d169de1bb399d226c12cdc666e0fa534149fc9fa7896ee61d406f` |
| Packer | `UPX` |
| Malware Family | `AgentTesla` |

---

# Conclusion

The investigation revealed a compromise of an IIS server through network reconnaissance, SMB share access, and the upload of a malicious ASP.NET webshell.

The attacker established a reverse shell over TCP port `4443`. Memory forensics identified the IIS worker process (`w3wp.exe`, PID `4332`) as the process handling the connection and spawning the malicious executable `updatenow.exe`.

Further static analysis revealed that the executable was packed using UPX. Threat-intelligence research associated its SHA-256 hash with AgentTesla and identified `cp8nl.hyperhost.ua` as its command-and-control domain.

This challenge demonstrates how network forensics, memory analysis, static malware inspection, and threat intelligence can be combined to reconstruct an intrusion.

**Safety note:** The malware sample should be analyzed in an isolated lab environment. Do not execute it on a normal workstation.