# XLMRat

### Lab Access Link: https://cyberdefenders.org/blueteam-ctf-challenges/xlmrat/

## Lab Overview
- **Category:** Network Forensics
- **Focus:** Malware delivery, PowerShell deobfuscation, reflective code loading, persistence, and MITRE ATT&CK mapping
- **Tools:** Wireshark, Python 3, ExifTool, `file`, `sha256sum`, VirusTotal

> Analyze in an isolated environment. Do not execute recovered malware or scripts.

## 1. Initial Malware Download (Q1)
1. Open the PCAP in Wireshark.
2. Apply:
   ```wireshark
   http.request
   ```
3. Identify requests for `xlm.txt` and `mdm.jpg`.
4. Right-click the `xlm.txt` request → **Follow → HTTP Stream**.
5. Record the first-stage URL:

   `http://45.126.209.4:222/xlm.txt`

The response contains a fragmented PowerShell command assembled from array entries.

## 2. Deobfuscate the First Stage
The `xlm.txt` script concatenates string fragments and constructs a PowerShell command to retrieve the second stage.

Key observations:
- `IEX` = PowerShell `Invoke-Expression`
- `New-Object Net.WebClient` creates a WebClient object
- `DownloadString` retrieves remote content as a string
- `mdm.jpg` is a misleading extension; its content is PowerShell text

Use Python to concatenate the fragments and reproduce the original substitutions. Confirm substitutions against the original script.

## 3. Inspect the Second Stage
1. Select the `mdm.jpg` HTTP request in Wireshark.
2. Right-click → **Follow → HTTP Stream**.
3. Export the response.
4. Inspect without executing:

   ```bash
   file mdm.jpg
   xxd -l 16 mdm.jpg
   grep -nE '\$hexString_pe|\$hexString_bbb|Reflection|WriteAllBytes|Assembly' mdm.jpg
   ```

The file is UTF-8 PowerShell text (with BOM), not a JPEG. It contains two underscore-separated hexadecimal payload strings:
- `$hexString_pe` — loader
- `$hexString_bbb` — secondary executable

## 4. Extract the PE Payloads
Use `extract_xlmrat.py` to parse the two hex strings, remove underscores, convert them using `bytes.fromhex()`, and write the files. This is static extraction; it does not execute the script.

Run:

```bash
python3 extract_xlmrat.py mdm.jpg
file loader_pe.exe secondary.exe
sha256sum loader_pe.exe secondary.exe
```

| Payload | Size | SHA256 |
|---|---:|---|
| `loader_pe.exe` | 76,288 bytes | `2c6c4cd045537e2586eab73072d790af362e37e6d4112b1d01f15574491296b8` |
| `secondary.exe` | 66,560 bytes | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |

Both payloads begin with the `MZ` PE signature.

## 5. Malware Family (Q4)
Search the SHA256 of `secondary.exe` on VirusTotal. Alibaba detection:

`Backdoor:MSIL/AsyncRat.a2786761`

This is an AsyncRAT-family backdoor detection.

## 6. PE Creation Timestamp (Q5)
Inspect the secondary executable:

```bash
exiftool secondary.exe
```

PE `Time Stamp`:

`2023:10:30 20:38:44+05:30`

UTC:

`2023-10-30 15:08:44 UTC`

Do not confuse the PE timestamp with the local file modification time.

## 7. LOLBin (Q6)
The script removes `#` characters from fragments to reconstruct:

`C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe`

`RegSvcs.exe` is a legitimate .NET utility abused for proxy execution. The loader passes the executable path and payload bytes to its `Execute` method.

## 8. Dropped Files and Persistence (Q7)
The script writes these files under `C:\Users\Public\`:

| File | Purpose |
|---|---|
| `Conted.ps1` | PowerShell loader/payload script |
| `Conted.bat` | Starts PowerShell hidden with execution-policy bypass |
| `Conted.vbs` | Launches the BAT file using `WScript.Shell` |

It registers a scheduled task:

- **Task:** `Update Edge`
- **Action:** `C:\Users\Public\Conted.vbs`
- **Trigger:** TimeTrigger
- **Repetition:** `PT2M` (every 2 minutes)

## 9. MITRE ATT&CK Mapping

| Behavior | Technique | ID |
|---|---|---|
| PowerShell execution | PowerShell | T1059.001 |
| VBScript execution | Visual Basic | T1059.005 |
| Regsvcs proxy execution | Regsvcs | T1218.009 |
| Scheduled task persistence | Scheduled Task/Job | T1053 |
| Reflective loading | Reflective Code Loading | T1620 |

## 10. Answers Summary

| Question | Finding |
|---|---|
| Q1 | `http://45.126.209.4:222/xlm.txt` |
| Q2 | Hosting provider for `45.126.209.4` — **fill in after IP/ASN lookup** |
| Q3 | `1eb7b02e18f67420f42b1d94e74f3b6289d92672a0fb1786c30c03d68e81d798` |
| Q4 | `Backdoor:MSIL/AsyncRat.a2786761` |
| Q5 | `2023-10-30 15:08:44 UTC` |
| Q6 | `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe` |
| Q7 | `Conted.ps1`, `Conted.bat`, `Conted.vbs` |

## Safety Notes
- Do not execute `xlm.txt`, `mdm.jpg`, or extracted PE files on a host system.
- Never invoke recovered code with `IEX`.
- Use static inspection and hash-based identification.
- Keep samples in an isolated analysis VM or directory.