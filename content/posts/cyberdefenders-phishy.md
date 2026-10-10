+++
title = "CyberDefenders - Phishy Lab Writeup"
date = 2026-10-10T00:00:00+07:00
draft = false
tags = ["CyberDefenders", "Windows Forensics", "Phishing", "Malware Analysis", "Registry", "Firefox"]
categories = ["Writeups"]
summary = "Investigating a fake iPhone giveaway through Windows registry artifacts, WhatsApp messages, malicious Office macros, Meterpreter configuration, and Firefox data."
ShowToc = true
TocOpen = false
+++

Phishy follows a fake iPhone giveaway from the initial WhatsApp conversation to a malicious Office document, a downloaded payload, and a credential-harvesting page. This writeup traces the evidence across the victim's Windows disk image.

**Tools:** FTK Imager, Registry Explorer, WhatsApp Viewer, oledump, olevba, CyberChef, VirusTotal, Autopsy, and Mozilla NSS.

| Evidence | Investigation focus |
| --- | --- |
| SYSTEM registry hive | Victim hostname |
| WhatsApp `msgstore.db` | Social engineering and document download URL |
| `IPhone-Winners.doc` | VBA streams and encoded commands |
| `Iphone.exe` | Malware identification and remote endpoint |
| Firefox `places.sqlite` | Phishing page in browsing history |
| Firefox profile files | Recovery of stored login credentials |

## Q1: What is the hostname of the victim machine?

To determine the hostname of the compromised machine, we start by examining the forensic disk image provided as part of the investigation. This image is in AD1 format, a forensic image format used by AccessData tools, which ensures the integrity of digital evidence. To access its contents, we utilize FTK Imager, a forensic imaging tool that allows us to mount and explore disk images without modifying the original data.

Mounting the image in read-only mode is crucial in forensic investigations to preserve the integrity of the evidence while enabling access to system files as if the drive were physically connected.

![Examining the AD1 evidence in FTK Imager](/images/imported/phishy/phishy-01.png)

Once mounted, the disk image appears as a logical drive on the forensic workstation, allowing us to navigate its file system. With the image mounted, we proceed to locate and analyze the SYSTEM registry hive, a critical component of Windows system configurations. The Windows registry is a database that stores essential settings and preferences for both the operating system and installed applications.

It consists of several registry hives, each responsible for specific system and user configurations. The SYSTEM hive, in particular, contains information related to system hardware, services, startup configurations, and network parameters. This registry file is typically stored in the `C:\Windows\System32\config` directory and is one of the most valuable sources of forensic evidence when investigating a compromised system.

To extract and analyze the SYSTEM hive, we use Registry Explorer, a forensic tool designed for in-depth registry analysis. This tool allows us to load offline registry hives from the forensic image, parse their contents, and view system settings in a structured format. Once the SYSTEM hive is loaded, we navigate through its hierarchical structure to locate the `ControlSet001\Control\ComputerName\ComputerName` key.

This key contains a value named `ComputerName`, which holds the hostname assigned to the machine. The hostname is an essential identifier that can help correlate forensic findings across network logs, security alerts, and other system artifacts.

![ComputerName value in the offline SYSTEM registry hive](/images/imported/phishy/phishy-02.png)

Extracting the hostname from the SYSTEM hive provides us with a crucial piece of information in our investigation. Identifying the machine’s name helps in tracing security incidents back to a specific endpoint, linking it to user activity, and correlating it with network infrastructure logs. This information can also be used to determine whether the compromised machine had prior security incidents or if it had been communicating with suspicious external entities.

Understanding the system’s identity allows security analysts to build a more comprehensive picture of the attack and assess the extent of the compromise. As can be seen in the above screenshot, the hostname of the infected machine is `WIN-NF3JQEU4G0T`

> **Answer:** `WIN-NF3JQEU4G0T`

## Q2: What is the messaging app installed on the victim machine?

To determine the messaging application installed on the victim's machine, we need to examine locations where user-installed applications and their data are commonly stored. Windows systems store user-specific application data in several locations, including the Program Files directory for system-wide installations and the `AppData` folder for user-specific configurations and temporary files. In this case, we focus on the `AppData` directory, as it often contains critical forensic artifacts related to applications installed or executed by the user.

The `AppData` folder is a hidden directory in Windows, located within a user’s profile at `C:\Users\<Username>\AppData`. It is divided into three subdirectories: Local, LocalLow, and Roaming, each serving different purposes. The Local folder contains application data that is specific to the system and is not synchronized across multiple devices.

This includes cache files, logs, and temporary data stored by applications. The Roaming folder stores settings and files that can be synced across devices if the user logs in with a domain account. The LocalLow folder, on the other hand, is used for applications with lower security permissions, such as browser plugins.

Since we are investigating applications installed for a specific user, we navigate to the Local subdirectory within the `AppData` folder. Inside, we find several application-related folders that contain configuration files, logs, and other remnants of installed software. Among these folders, we identify a directory named WhatsApp, indicating that the WhatsApp messaging application is present on the system.

![WhatsApp application directory in the victim's profile](/images/imported/phishy/phishy-03.png)

The WhatsApp folder in the Local directory confirms that the application was installed and likely used by the victim. Further analysis of this folder could reveal logs, cache files, or stored message history that might be relevant to the investigation.

> **Answer:** `WhatsApp`

## Q3: The attacker tricked the victim into downloading a malicious document. Provide the full download URL.

Analyzing the full download URL of the malicious document requires examining the WhatsApp message history stored on the compromised machine. Messaging applications such as WhatsApp store their chat logs, attachments, and metadata in local databases, which can serve as critical forensic evidence. In this case, the forensic examination of the `AppData` directory revealed that WhatsApp was installed, and its files were stored under the Roaming folder.

This location suggests that user data, including chat history, was retained even after restarting or logging out of the application. One of the most important files in this directory is `msgstore.db`, a SQLite database file that logs all chat messages, including sent and received texts, timestamps, sender details, and any shared links or attachments.

![Locating the WhatsApp msgstore.db database](/images/imported/phishy/phishy-04.png)

SQLite is a self-contained database format used by many applications due to its lightweight nature, making it a prime target for forensic investigations. Since this file contains valuable data about conversations the victim engaged in, it is crucial to extract and analyze its contents to trace potential indicators of compromise. For this analysis, WhatsApp Viewer is used, a forensic tool specifically designed to parse WhatsApp `msgstore.db` databases and display chat logs in a structured format.

Loading the database into this tool provides a clear view of the conversations that took place on the victim’s system. Scanning through the chat history, an exchange is identified in which the attacker manipulates the victim into believing they have won an iPhone giveaway. Social engineering tactics are evident in the conversation, where the attacker persuades the victim to download a document containing the supposed list of winners.

Within the conversation, a suspicious URL is found leading to a malicious document named `IPhone-Winners.doc`

![WhatsApp conversation containing the malicious document URL](/images/imported/phishy/phishy-05.png)

The attacker provides this link under the pretense of verifying the contest results, tricking the victim into downloading it. The URL associated with this file is `http://appIe.com/IPhone-Winners.doc`. This URL is highly deceptive, as it mimics Apple’s domain structure to gain the victim’s trust.

However, such links often lead to phishing sites, malicious payloads, or trojanized documents designed to execute harmful scripts upon opening.

> **Answer:** `http://appIe.com/IPhone-Winners.doc`

## Q4: Multiple streams contain macros in the document. Provide the number of the highest stream.

Microsoft Office documents can contain multiple embedded streams, which are separate data structures inside the file. These streams store different components, including document content, metadata, and potentially malicious macros. Macros are small scripts written in Visual Basic for Applications (VBA) that can automate tasks but are frequently exploited by attackers to execute malicious code on a victim’s machine.

Malicious actors often embed macros within documents to initiate malware infections, typically through phishing campaigns where users are tricked into enabling macros, leading to the execution of harmful scripts. To analyze the embedded macros in the `IPhone-Winners.doc` file, we use oledump, a Python-based forensic tool developed by Didier Stevens. Oledump allows us to inspect OLE (Object Linking and Embedding) files, which are commonly used in Microsoft Office documents.

This tool lists all streams inside the document and helps identify those containing VBA macros, denoted by the letter "M." By executing oledump on the document, we obtain a list of streams along with their identifiers and sizes.

![OLE streams showing macro stream 10, Macros/VBA/iphoneevil](/images/imported/phishy/phishy-06.png)

The output reveals multiple streams containing macros, each labeled under `Macros/VBA/`. Among them, the highest-numbered stream is Stream 10, labeled `Macros/VBA/iphoneevil`, indicating it contains potentially malicious code. The presence of this stream suggests that the attacker used VBA to execute harmful instructions upon opening the document.

The size of this macro-containing stream also suggests that it might hold complex scripting intended to bypass security mechanisms.

Identifying the highest macro stream number is crucial in forensic analysis because it helps focus further investigations on the most likely payload carrier within the document. The next steps in analysis would involve extracting and deobfuscating the macro to understand its functionality, such as whether it downloads additional payloads, modifies system settings, or steals user information.

> **Answer:** `10`

## Q5: The macro executed a program. Provide the program name?

Malicious macros embedded in Microsoft Office documents are often designed to execute external programs, download additional payloads, or perform system modifications without user consent. In this case, analyzing the VBA macro within the `IPhone-Winners.doc` file reveals that it executes a command, which we need to deobfuscate to determine its final payload. Attackers commonly obfuscate their malicious scripts using encoding techniques such as Base64 to evade detection by security tools.

To analyze the macro, we use olevba, a tool from the oletools suite that specializes in extracting and analyzing VBA macros from Microsoft Office documents. Running olevba with the `--deobf` flag allows us to deobfuscate scripts and reveal hidden functionality. The analysis detects multiple suspicious patterns, including the use of PowerShell, Shell execution commands, and Base64-encoded strings, all of which are indicators of malicious activity.

![VBA analysis revealing PowerShell and encoded content](/images/imported/phishy/phishy-07.png)

The presence of encoded content suggests that the macro is attempting to execute a secondary payload in an obfuscated manner. Extracting the encoded Base64 string from the macro allows us to reconstruct the command being executed. Using CyberChef, a web-based forensic tool designed for data transformations, we decode the Base64-encoded content to reveal its original form.

The decoded output confirms that the macro executes a PowerShell command that downloads a file from an external source. The command uses the `Invoke-WebRequest` function to retrieve a file from the following URL `http://appIe.com/Iphone.exe`

![Decoding the macro's Base64 content in CyberChef](/images/imported/phishy/phishy-08.png)

The retrieved file is saved in the system’s Temp directory with the name `IPhone.exe`. This confirms that the macro’s purpose is to download and execute a malicious executable. The use of PowerShell for remote payload retrieval is a common technique in phishing attacks, as it allows attackers to dynamically fetch additional malware components without embedding them directly within the document.

This approach helps evade static detection mechanisms while maintaining control over the infection process.

> **Answer:** `PowerShell`

## Q6: The macro downloaded a malicious file. Provide the full download URL.

Based on the analysis in the previous question, the malicious file was downloaded from the URL `http://appIe.com/Iphone.exe`.

> **Answer:** `http://appIe.com/Iphone.exe`

## Q7: Where was the malicious file downloaded to? (Provide the full path)

![Downloaded executable in the Temp directory](/images/imported/phishy/phishy-09.png)

Based on the analysis of the decoded command in Q5, the file was downloaded to the path: `C:\Temp\Iphone.exe`

> **Answer:** `C:\Temp\Iphone.exe`

## Q8: What is the name of the framework used to create the malware?

The computed hash is `7c827274c062374e992eb8f33d0c188c`, which provides a reliable identifier for checking the file's reputation in threat intelligence platforms.

![Computing the hash of the downloaded executable](/images/imported/phishy/phishy-10.png)

Next, we use VirusTotal, a widely used online malware analysis service that aggregates detections from multiple antivirus engines. VirusTotal allows security researchers to upload and scan files or search by hash values to determine if a file has been flagged as malicious. By querying VirusTotal with the computed hash, we find that 68 out of 73 security vendors have flagged the file as malicious, indicating that it is a known malware sample.

![VirusTotal detections identifying Meterpreter](/images/imported/phishy/phishy-11.png)

The detection names provided by various security vendors reveal that the malware contains Meterpreter, a payload commonly associated with the Metasploit Framework. Meterpreter is a powerful, stealthy penetration testing tool that allows attackers to establish remote control over a compromised system. It operates as an in-memory payload, avoiding detection by traditional file-based antivirus solutions.

Multiple antivirus engines classify the malware as Win32:Meterpreter-C, Backdoor.Win/Meterpreter.A, and Trojan.Win32.Shell, confirming that it was likely generated using Metasploit. Metasploit is an advanced penetration testing framework widely used by ethical hackers and adversaries alike to exploit vulnerabilities, deploy payloads, and establish persistent access to compromised machines. It provides a vast collection of exploits, payloads, and post-exploitation tools that facilitate command execution, privilege escalation, and lateral movement.

Attackers often use Metasploit’s msfvenom utility to generate custom payloads, including Meterpreter-based backdoors, which can be embedded in phishing documents or malicious executables. The detection of Meterpreter in the analyzed file strongly indicates that the malware was created using Metasploit Framework. This finding highlights that the attacker likely leveraged Metasploit’s capabilities to maintain covert access to the victim’s system, potentially allowing for further exploitation, data exfiltration, or lateral movement within the network.

> **Answer:** `Metasploit`

## Q9: What is the attacker's IP address?

Identifying the attacker's IP address requires analyzing the Meterpreter payload configuration embedded in the malicious `IPhone.exe` file. When adversaries generate a Meterpreter payload using the Metasploit Framework, they specify a command-and-control (C2) server to which the infected machine connects after execution. This configuration is crucial because it provides the remote IP address and port that the malware uses to establish communication with the attacker's infrastructure.

Using VirusTotal , we analyze the behavior of the malware sample and locate the decoded text section within the report. This section often contains extracted strings that reveal hardcoded configurations, including C2 addresses.

![Payload configuration showing the remote IP and port](/images/imported/phishy/phishy-12.png)

The extracted information from the decoded text indicates that the malware is configured to connect to a remote server at `155.94.69.27` on port 4242. The details also classify this as a Metasploit Connect session, reinforcing that the malware was created using Metasploit and designed to establish a backdoor connection to the attacker's system. The presence of a Meterpreter shell means that once executed, the infected machine would open a reverse connection to the attacker's IP.

This allows the attacker to execute commands remotely, upload or download files, escalate privileges, and move laterally within the victim’s network. The choice of port 4242 is consistent with default Metasploit settings for reverse TCP payloads, suggesting the attack was orchestrated using standard tools available within the framework.

> **Answer:** `155.94.69.27`

## Q10: The fake giveaway used a login page to collect user information. Provide the full URL of the login page?

To identify the full URL of the login page used in the fake giveaway scam, we need to analyze the browser history stored in the victim’s Mozilla Firefox profile. Web browsers save visited websites, login attempts, and form submissions in dedicated SQLite database files, which can be extracted and examined for forensic investigations. In the case of Mozilla Firefox, the browsing history is stored in a file named `places.sqlite`, which logs all visited URLs, page titles, visit timestamps, and other metadata.

The `places.sqlite` file is located in the `AppData` directory under the Firefox user profile path `C:\Users\<Username>\AppData\Roaming\Mozilla\Firefox\Profiles\<ProfileName>\places.sqlite`. This file is a critical artifact in forensic investigations, as it records not only visited URLs but also frequency and timestamps, allowing analysts to reconstruct user browsing activity. To extract and analyze the contents of `places.sqlite`, we use Autopsy, a forensic tool that provides a structured interface for examining disk images and system artifacts, including browser history databases.

Loading the `places.sqlite` file into Autopsy, we navigate to the `moz_places` table, which contains a list of visited URLs along with metadata such as visit count, last visit timestamp, and referring hosts. By filtering through the stored entries, we identify a URL that matches the theme of the phishing scam `http://appIe.competitions.com/login.php`

![Firefox history containing the fake giveaway login page](/images/imported/phishy/phishy-13.png)

> **Answer:** `http://appIe.competitions.com/login.php`

## Q11: What is the password the user submitted to the login page?

Use FTK Imager to extract the `logins.json`, `key4.db`, and `cert9.db` files from the Firefox profile. Specifically, `logins.json` contains encrypted login information, `key4.db` holds the key data for decryption services, and `cert9.db` stores the Firefox certificate database. Then, use Mozilla NSS to recover the login credentials stored in the browser.

![Firefox profile files used for credential recovery](/images/imported/phishy/phishy-14.png)

![Recovered Firefox login credentials](/images/imported/phishy/phishy-15.png)

The extracted credentials reveal that the username used for login was Semah, and the password submitted was `GacsriicUZMY4xiAF4yl`

> **Answer:** `GacsriicUZMY4xiAF4yl`

## Answer Summary

| Question | Answer |
| --- | --- |
| Q1 | `WIN-NF3JQEU4G0T` |
| Q2 | `WhatsApp` |
| Q3 | `http://appIe.com/IPhone-Winners.doc` |
| Q4 | `10` |
| Q5 | `PowerShell` |
| Q6 | `http://appIe.com/Iphone.exe` |
| Q7 | `C:\Temp\Iphone.exe` |
| Q8 | `Metasploit` |
| Q9 | `155.94.69.27` |
| Q10 | `http://appIe.competitions.com/login.php` |
| Q11 | `GacsriicUZMY4xiAF4yl` |
