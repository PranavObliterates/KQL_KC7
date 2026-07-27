# Section 2: Tummy Trouble, make it Double 🤢

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
- [Question 27](#question-27)
- [Question 28](#question-28)
- [Question 29](#question-29)
- [Question 30](#question-30)
- [Question 31](#question-31)
- [Question 32](#question-32)
- [Question 33](#question-33)
- [Question 34](#question-34)
- [Question 35](#question-35)
- [Question 36](#question-36)
- [Question 37](#question-37)
- [Question 38](#question-38)
- [Question 39](#question-39)
- [Question 40](#question-40)
- [Question 41](#question-41)
- [Question 42](#question-42)
- [Question 43](#question-43)
- [Question 44](#question-44)
- [Question 45](#question-45)
- [Question 46](#question-46)
- [Question 47](#question-47)
- [Question 48](#question-48)
- [Question 49](#question-49)
- [Question 50](#question-50)

---

## Question 1

What's Delphia's username?

### KQL Query

```kql
Employees
| where name has "Delphia"
| project username
```

### Answer

`deevans`

---

## Question 2

What's the company domain?

### KQL Query

```kql
Employees
| where name has "Delphia"
| project company_domain
```

### Answer

`daiwokfoods.com`

---

## Question 3

What's the hostname of Delphia's computer?

### KQL Query

```kql
Employees
| where name has "Delphia"
| project hostname
```

### Answer

`ABVJ-MACHINE`

---

## Question 4

What is Delphia's Role at Dai Wok Foods?

### KQL Query

```kql
Employees
| where name has "Delphia"
| project role
```

### Answer

`Restaurant Staff`

---

## Question 5

When was the first alert related to Delphia?

### KQL Query

```kql
SecurityAlerts
| where description has_any ("ABVJ-MACHINE", "deevans")
| project timestamp
```

### Answer

`2023-04-04T10:14:35Z`

---

## Question 6

What's the full subject line that was listed on this alert?

### KQL Query

```kql
SecurityAlerts
| where description has_any ("ABVJ-MACHINE", "deevans")
| project description
```

### Answer

`[EXTERNAL] Formal action on food poisoning`

---

## Question 7

What IP address is assigned to her computer?

### KQL Query

```kql
Employees
| where name has "Delphia"
| project ip_addr
```

### Answer

`192.168.0.31`

---

## Question 8

What is Delphia's email address?

### KQL Query

```kql
Employees
| where name has "Delphia"
| project email_addr
```

### Answer

`delphia_evans@daiwokfoods.com`

---

## Question 9

How many emails did she receive?

### KQL Query

```kql
Email
| where recipient == "delphia_evans@daiwokfoods.com"
```

### Answer

`26`

---

## Question 10

How many external emails did Delphia receive?

### KQL Query

```kql
Email
| where recipient == "delphia_evans@daiwokfoods.com"
| where sender !endswith "@daiwokfoods.com"
```

### Answer

`15`

---

## Question 11

When was the email sent to her?

### KQL Query

```kql
Email
| where subject == "[EXTERNAL] Formal action on food poisoning"
| where recipient == "delphia_evans@daiwokfoods.com"
| project timestamp
```

### Answer

`2023-04-02T20:40:54Z`

---

## Question 12

Who sent the email?

### KQL Query

```kql
Email
| where subject == "[EXTERNAL] Formal action on food poisoning"
| where recipient == "delphia_evans@daiwokfoods.com"
| project sender
```

### Answer

`county.county@yahoo.com`

---

## Question 13

How many emails did this email address send to Dai Wok employees?

### KQL Query

```kql
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
```

### Answer

`14`

---

## Question 14

Let's take the unique `reply_to` email addresses and find more sender addresses from those.

How many emails are there?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

Email
| where reply_to in (unique_reply_to)
```

### Answer

`43`

---

## Question 15

How many unique sender addresses did you find?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

Email
| where sender in (unique_reply_to)
| distinct reply_to
```

### Answer

`5`

---

## Question 16

(OPTIONAL QUESTION) - How many total emails were sent by this threat actor?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

let all_badmails =
Email
| where sender in (unique_reply_to)
| distinct reply_to;

Email
| where sender in (all_badmails)
```

### Answer

`64`

---

## Question 17

How many unique URLs are there?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

Email
| where reply_to in (unique_reply_to)
| extend url = tostring(parse_url(link).Host)
| distinct url
```

### Answer

`12`

---

## Question 18

What is the domain name of the URL found?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

let bad_url =
Email
| where reply_to in (unique_reply_to)
| extend url = tostring(parse_url(link).Host)
| distinct url;

OutboundNetworkEvents
| where url has_any (bad_url)
| project domain_name = tostring(parse_url(url).Host)
```

### Answer

`complaints-cityofficialsfood.com`

---

## Question 19

Who clicked on the link?

### KQL Query

```kql
let who_click_ip =
OutboundNetworkEvents
| where url == "https://complaints-cityofficialsfood.com/search/published/images/images/large_order.xlsx"
| project src_ip;

Employees
| where ip_addr in (who_click_ip)
```

### Answer

`John Garcia`

---

## Question 20

What is their role in the company?

### KQL Query

```kql
Employees
| where name == "John Garcia"
| project role
```

### Answer

`Logistics Coordinator`

---

## Question 21

What is their hostname?

### KQL Query

```kql
Employees
| where name == "John Garcia"
| project hostname
```

### Answer

`LVJW-LAPTOP`

---

## Question 22

Do we see their email address in the threat actor emails?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

Email
| where reply_to in (unique_reply_to)
| where recipient == "john_garcia@daiwokfoods.com"
```

### Answer

`No`

---

## Question 23

When did this employee receive the suspicious email?

### KQL Query

```kql
Email
| where recipient == "john_garcia@daiwokfoods.com"
| where link == "https://complaints-cityofficialsfood.com/search/published/images/images/large_order.xlsx"
```

### Answer

`2023-04-03T18:04:56Z`

---

## Question 24

(OPTIONAL QUESTION) - How many distinct roles were targeted by the threat actor?

### KQL Query

```kql
let unique_reply_to =
Email
| where sender == "county.county@yahoo.com"
| where recipient endswith "@daiwokfoods.com"
| distinct reply_to;

let all_badmails =
Email
| where sender in (unique_reply_to)
| distinct reply_to;

Email
| where sender in (all_badmails)
| lookup Employees on $left.recipient == $right.email_addr
| distinct role
```

### Answer

`15`

---

## Question 25

What's the `reply_to` email address of the suspicious email?

### KQL Query

```kql
Email
| where recipient == "john_garcia@daiwokfoods.com"
| where link == "https://complaints-cityofficialsfood.com/search/published/images/images/large_order.xlsx"
| project reply_to
```

### Answer

`service_official@yandex.com`

---

## Question 26

What country is the email domain from?

### Notes

- Perform OSINT on the `yandex.com` domain using a search engine.

### Answer

`Russia`

---

## Question 27

How many PassiveDNS records are related to that domain?

### KQL Query

```kql
PassiveDns
| where domain == "complaints-cityofficialsfood.com"
```

### Answer

`9`

---

## Question 28

Which IP address did the domain resolve to at the time nearest the email activity?

### KQL Query

```kql
PassiveDns
| where domain == "complaints-cityofficialsfood.com"
```

### Notes

- Review the record closest to `2023-04-03T18:04:56Z`.

### Answer

`179.58.169.157`

---

## Question 29

What country does this IP appear to be located in?

### Notes

- Use a GeoIP service such as MaxMind or Censys.

### Answer

`Bolivia`

---

## Question 30

How many InboundNetworkEvents are related to that IP address?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "179.58.169.157"
| count
```

### Answer

`3`

---

## Question 31

What was the earliest thing the IP address searched for?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "179.58.169.157"
| sort by timestamp asc
```

### Notes

- Replace `%20` with a space.

### Answer

`store managers`

---

## Question 32

How many records total were found using all IPs associated with the domain?

### KQL Query

```kql
let all_ips =
PassiveDns
| where domain == "complaints-cityofficialsfood.com"
| distinct ip;

InboundNetworkEvents
| where src_ip in (all_ips)
```

### Answer

`49`

---

## Question 33

When was the earliest timestamp observed?

### KQL Query

```kql
let all_ips =
PassiveDns
| where domain == "complaints-cityofficialsfood.com"
| distinct ip;

InboundNetworkEvents
| where src_ip in (all_ips)
| summarize min(timestamp)
```

### Answer

`2023-03-26T01:20:14Z`

---

## Question 34

How many distinct source IP addresses were used by the compromised employee to log in?

### KQL Query

```kql
AuthenticationEvents
| where username == "jogarcia"
| distinct src_ip
```

### Answer

`2`

---

## Question 35

What country is the public IP address from?

### Notes

- Perform a GeoIP lookup for `2.20.114.29`.

### Answer

`Italy`

---

## Question 36

How many AuthenticationEvents are related to that IP address?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "2.20.114.29"
```

### Answer

`12`

---

## Question 37

What filename is referenced at the end of the suspicious URL?

### KQL Query

```kql
Email
| where recipient == "john_garcia@daiwokfoods.com"
| where link == "https://complaints-cityofficialsfood.com/search/published/images/images/large_order.xlsx"
| extend paths = tostring(parse_url(link).Path)
| extend filename = tostring(parse_path(paths).Filename)
| project filename
```

### Answer

`large_order.xlsx`

---

## Question 38

How many emails reference the same filename?

### KQL Query

```kql
Email
| where link contains "large_order.xlsx"
```

### Answer

`13`

---

## Question 39

How many host machines have this file?

### KQL Query

```kql
FileCreationEvents
| where filename == "large_order.xlsx"
| distinct hostname
```

### Answer

`1`

---

## Question 40

Where was this file located on the host machine?

### KQL Query

```kql
FileCreationEvents
| where filename == "large_order.xlsx"
| project path
```

### Answer

`C:\Users\jogarcia\Downloads\large_order.xlsx`

---

## Question 41

When was this file created on the host machine?

### KQL Query

```kql
FileCreationEvents
| where filename == "large_order.xlsx"
| project timestamp
```

### Answer

`2023-04-03T18:39:12Z`

---

## Question 42

What's the SHA256 hash of this file?

### KQL Query

```kql
FileCreationEvents
| where filename == "large_order.xlsx"
| project sha256
```

### Answer

`b9d3c969135f1e9abe22fd744c691ec1d1bc0853beffe5aed3f8b78b3d738501`

---

## Question 43

Let's use VirusTotal to search for this SHA256 hash.

Were there any results?

### Notes

VirusTotal search (defanged):

```text
hxxps://www.virustotal.com/gui/search?query=b9d3c969135f1e9abe22fd744c691ec1d1bc0853beffe5aed3f8b78b3d738501
```

### Answer

`No`

---

## Question 44

How many ProcessEvents are associated with this compromised host?

### KQL Query

```kql
ProcessEvents
| where hostname == "LVJW-LAPTOP"
```

### Answer

`466`

---

## Question 45

What's the name of the file from the `process_commandline` that occurs not long after the file was created?

### KQL Query

```kql
ProcessEvents
| where hostname == "LVJW-LAPTOP"
| where timestamp >= datetime(2023-04-03T18:39:12.000Z)
```

### Notes

- Review the process command line shortly after the spreadsheet is created.
- Look for the PowerShell script.

### Answer

`c5k3fsys.3bp.ps1`

---

## Question 46

What's the `parent_process_hash`?

### Notes

- Use the results from the previous query.

### Answer

`662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779`

---

## Question 47

Using VirusTotal, search the `parent_process_hash`.

What is the popular threat label?

### Notes

VirusTotal lookup (defanged):

```text
hxxps://www.virustotal.com/gui/file/662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779
```

### Answer

`trojan.powershell/malgent`

---

## Question 48

What threat actor is this file associated with?

### Notes

VirusTotal Community lookup (defanged):

```text
hxxps://www.virustotal.com/gui/file/662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779/community
```

### Answer

`FIN7`

---

## Question 49

What is the MD5 hash of this file?

### Notes

VirusTotal Details lookup (defanged):

```text
hxxps://www.virustotal.com/gui/file/662124b0c998fd0826c192514b1f57f8002f2ab031996aa6dd7832f561679779/details
```

### Answer

`d405909fd2fd021372444b7b36a3b806`

---

## Question 50

What type of operations did the cybersecurity company mention this threat actor shifted to doing?

### Notes

- Perform OSINT on **FIN7** and the referenced threat report.

### Answer

`ransomware`

---