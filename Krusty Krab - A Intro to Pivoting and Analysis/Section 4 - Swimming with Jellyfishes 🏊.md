# Section 4: Swimming with Jellyfishes 🏊

## Table of Contents
- [Question 1](#question-1)
- [Question 2](#question-2)
- [Question 3](#question-3)
- [Question 4](#question-4)
- [Question 5](#question-5)
- [Question 6](#question-6)
- [Question 7](#question-7)
- [Question 8](#question-8)
- [Question 9](#question-9)
- [Question 10](#question-10)
- [Question 11](#question-11)
- [Question 12](#question-12)
- [Question 13](#question-13)
- [Question 14](#question-14)
- [Question 15](#question-15)
- [Question 16](#question-16)
- [Question 17](#question-17)
- [Question 18](#question-18)
- [Question 19](#question-19)
- [Question 20](#question-20)
- [Question 21](#question-21)
- [Question 22](#question-22)
- [Question 23](#question-23)
- [Question 24](#question-24)
- [Question 25](#question-25)
- [Question 26](#question-26)

---

## Question 1

At `2023-03-28T05:36`, Timothy Graham received a suspicious email.

Who sent this email?

### KQL Query

```kql
let email_timothy =
Employees
| where name has "Timothy Graham"
| project email_addr;

Email
| where recipient in (email_timothy)
| where timestamp >= datetime(2023-03-28T05:36)
| project timestamp, sender
```

Reviewing the email received by Timothy Graham at the specified time reveals the suspicious sender.

### Answer

`legal.vendor@protonmail.com`

---

## Question 2

What was the subject of the email in Question 1?

### KQL Query

```kql
let email_timothy =
Employees
| where name has "Timothy Graham"
| project email_addr;

Email
| where recipient in (email_timothy)
| where sender == "legal.vendor@protonmail.com"
| project subject
```

### Answer

`[EXTERNAL] Holographic meatloaf! The new hot trend!`

---

## Question 3

What domain was observed in the links sent in Question 1?

### KQL Query

```kql
let email_timothy =
Employees
| where name has "Timothy Graham"
| project email_addr;

Email
| where recipient in (email_timothy)
| where sender == "legal.vendor@protonmail.com"
| extend dom = tostring(parse_url(link).Host)
| project dom
```

### Answer

`chumsecret.biz`

---

## Question 4

When did Timothy Graham click on the link?

Provide the full timestamp.

### KQL Query

The suspicious email contains a link to:

```text
hxxp://chumsecret[.]biz/published/search/Jellyfish_Guide.pptx
```

Timothy Graham's IP address is `192.168.0.146`. We can use it to identify his outbound request to the malicious domain:

```kql
OutboundNetworkEvents
| where url contains "chumsecret.biz"
| where src_ip == "192.168.0.146"
```

### Answer

`2023-03-28T08:43:23Z`

---

## Question 5

When did the Jellyfish Guide appear on Timothy Graham's machine?

### KQL Query

```kql
FileCreationEvents
| where filename contains "Jellyfish_Guide.pptx"
| where username == "tigraham"
| project timestamp
```

### Answer

`2023-03-28T08:44:20Z`

---

## Question 6

What was the SHA256 hash of the Jellyfish Guide?

### KQL Query

```kql
FileCreationEvents
| where filename contains "Jellyfish_Guide.pptx"
| where username == "tigraham"
| project sha256
```

### Answer

`4a64ffb707020fc077bb3c1f25c8cba5c0bb024679a82325baaab3374706b44e`

---

## Question 7

What file was created on Timothy's computer shortly after he downloaded the guide?

Provide the full path.

### KQL Query

```kql
FileCreationEvents
| where timestamp >= datetime(2023-03-28T08:44:20.000Z)
| where username == "tigraham"
```

Review the file creation events immediately following the creation of `Jellyfish_Guide.pptx`.

The suspicious executable appears shortly afterwards.

### Answer

`C:\SecretFormular\krabbypatty.exe`

---

## Question 8

The file that was dropped was uploaded to VirusTotal.

What filename was it uploaded as?

### KQL Query

First, examine the file creation activity following the Jellyfish Guide download:

```kql
FileCreationEvents
| where timestamp >= datetime(2023-03-28T08:44:20.000Z)
| where username == "tigraham"
```

The suspicious `krabbypatty.exe` file has the following SHA256:

```text
974a5796a0e00057571f51e2092524af9da7971a2933c6b9b12293cf00c6cc00
```

Search the hash on VirusTotal:

```text
hxxps://www[.]virustotal[.]com/gui/file/974a5796a0e00057571f51e2092524af9da7971a2933c6b9b12293cf00c6cc00
```

VirusTotal shows that the sample was uploaded under a DLL filename.

### Answer

`CX3VBWML.dll`

---

## Question 9

The `.exe` malware created a PowerShell process on Timothy's computer.

What IP address was observed inside that command?

### KQL Query

```kql
ProcessEvents
| where username contains "tigraham"
| where timestamp >= datetime(2023-03-28T08:44:20.000Z)
```

Review the events where `krabbypatty.exe` appears as the parent process.

The subsequent PowerShell command contains an external IP address.

### Answer

`59.240.32.173`

---

## Question 10

At `2023-03-28T05:36`, Timothy Graham received a suspicious email.

Who sent this email?

### KQL Query

```kql
Email
| where recipient == "timothy_graham@krustykrab.com"
| where timestamp >= datetime(2023-03-28T05:36:00.000Z)
```

Reviewing the emails received on March 28 shows the suspicious sender.

### Answer

`legal.vendor@protonmail.com`

---

## Question 11

How many computers at the Krusty Krab have executed PowerShell commands similar to the activity identified in Question 9?

### KQL Query

From Question 9, the suspicious PowerShell process has the following process hash:

```text
83ac309fb62394a61b9caa843087f699552de2fd2b389c1059fe70431305c672
```

Use the hash to identify every host where the same process was observed:

```kql
ProcessEvents
| where process_hash == "83ac309fb62394a61b9caa843087f699552de2fd2b389c1059fe70431305c672"
| distinct hostname
```

### Answer

`28`

---

## Question 12

What was the most prevalent IP seen in Question 11?

### KQL Query

```kql
ProcessEvents
| where process_hash == "83ac309fb62394a61b9caa843087f699552de2fd2b389c1059fe70431305c672"
| summarize count() by process_commandline
| sort by count_ desc
```

The most frequently occurring command line contains the most prevalent IP address.

### Answer

`157.99.160.12`

---

## Question 13

Someone reported a suspicious command on a computer. They saw a firewall rule being added to `"Block Outgoing Traffic"`.

How many machines was this command observed on?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "block"
| distinct hostname
```

### Answer

`8`

---

## Question 14

On which host did the activity concerning the firewall rule first occur?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "block"
```

Review the events chronologically. The earliest firewall rule activity occurred on the following host.

### Answer

`7EJH-LAPTOP`

---

## Question 15

When did the activity concerning the firewall rule first occur?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "block"
```

Using the same earliest event identified in Question 14, inspect its timestamp.

### Answer

`2023-03-17T07:53:53Z`

---

## Question 16

Right after the suspicious firewall command was executed, the attackers used a "copycat" command to steal data from the machine.

What was the name of the process they used for this command?

### KQL Query

The suspicious firewall process has the following hash:

```text
600c19d3329ff6a4adcc99ca5576bcbeb03a04c56d1040ea77d53afe41793494
```

Serialize the events so that `next()` can inspect the command executed immediately afterwards:

```kql
ProcessEvents
| where hostname == "7EJH-LAPTOP"
| serialize
| extend next_cmdline = next(process_commandline)
| extend next_parentproc = next(parent_process_name)
| where process_hash == "600c19d3329ff6a4adcc99ca5576bcbeb03a04c56d1040ea77d53afe41793494"
| project next_cmdline, next_parentproc
```

The following command shows the use of `rclone`.

### Answer

`rclone.exe`

---

## Question 17

To what domain did they send the data that they stole?

### KQL Query

Use the same pivot from Question 16:

```kql
ProcessEvents
| where hostname == "7EJH-LAPTOP"
| serialize
| extend next_cmdline = next(process_commandline)
| extend next_parentproc = next(parent_process_name)
| where process_hash == "600c19d3329ff6a4adcc99ca5576bcbeb03a04c56d1040ea77d53afe41793494"
| project next_cmdline, next_parentproc
```

Inspect the `rclone` command line. The destination contains the domain used for data exfiltration.

### Answer

`computer-wifesecret.com`

---

## Question 18

Right before the suspicious firewall command was executed, the attackers used a command to collect sensitive files into a staging directory.

What is the name of the process they used?

### KQL Query

Because we need the process immediately before the suspicious firewall activity, serialize the events and use `prev()`:

```kql
ProcessEvents
| where hostname == "7EJH-LAPTOP"
| serialize
| extend prev_proc = prev(process_name)
| where process_hash == "600c19d3329ff6a4adcc99ca5576bcbeb03a04c56d1040ea77d53afe41793494"
| project prev_proc
```

### Answer

`powershell.exe`

---

## Question 19

The victim host in Question 14 downloaded a suspicious `.exe` file on the day before the suspicious firewall command was executed.

What is the name of that file?

### KQL Query

The firewall activity occurred at:

```text
2023-03-17T07:53:53Z
```

Search file creation activity on the compromised host from the previous day until the firewall activity:

```kql
FileCreationEvents
| where hostname == "7EJH-LAPTOP"
| where timestamp between (
    datetime(2023-03-16T00:00:00.000Z) ..
    datetime(2023-03-17T07:53:53.000Z)
)
```

Reviewing the files created during this period reveals the suspicious executable.

### Answer

`krabbypatty.exe`

---

## Question 20

What PDF file was observed on the victim's machine immediately before the `.exe` file appeared?

### KQL Query

```kql
FileCreationEvents
| where hostname == "7EJH-LAPTOP"
| where timestamp between (
    datetime(2023-03-16T00:00:00.000Z) ..
    datetime(2023-03-17T07:53:53.000Z)
)
| serialize
| extend pdf_file = prev(filename)
| where filename has ".exe"
| project pdf_file
```

This identifies the file creation event immediately preceding the suspicious executable.

### Answer

`Free_Money.pdf`

---

## Question 21

What is the name of the user whose host was compromised in Question 14?

### KQL Query

```kql
Employees
| where hostname == "7EJH-LAPTOP"
```

### Answer

`Robert Vinson`

---

## Question 22

When did the employee in Question 21 click on a link that would have led him to download the file identified in Question 20?

### KQL Query

Robert Vinson's assigned IP address is:

```text
192.168.2.76
```

Search his outbound network activity for the suspicious PDF:

```kql
OutboundNetworkEvents
| where url contains "Free_Money.pdf"
| where src_ip == "192.168.2.76"
```

### Answer

`2023-03-16T10:55:51Z`

---

## Question 23

What domain was observed in the link that the user in Question 21 clicked?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "Free_Money.pdf"
| where src_ip == "192.168.2.76"
| extend domain = tostring(parse_url(url).Host)
| project domain
```

### Answer

`burgers-formula.biz`

---

## Question 24

When did the user in Question 21 receive an email containing the domain from Question 23?

### KQL Query

```kql
Email
| where recipient == "robert_vinson@krustykrab.com"
| where link contains "burgers-formula.biz"
| project timestamp
```

### Answer

`2023-03-16T04:43:38Z`

---

## Question 25

How many domains share the same IP as the domain in Question 23?

### KQL Query

First, retrieve the IP addresses associated with `burgers-formula.biz`:

```kql
let the_ip =
PassiveDns
| where domain == "burgers-formula.biz"
| project ip;

PassiveDns
| where ip in (the_ip)
| distinct domain
```

This pivot identifies all domains sharing infrastructure with the suspicious domain.

### Answer

`5`

---

## Question 26

How many emails were sent to Krusty Krab employees containing domains from Question 25?

### KQL Query

First, retrieve the IP infrastructure associated with `burgers-formula.biz`, then identify all domains sharing those IP addresses:

```kql
let the_ip =
PassiveDns
| where domain == "burgers-formula.biz"
| project ip;

let bad_doms =
PassiveDns
| where ip in (the_ip)
| distinct domain;

Email
| where link has_any (bad_doms)
```

The resulting email events represent messages containing links associated with the identified infrastructure.

### Answer

`10`

---