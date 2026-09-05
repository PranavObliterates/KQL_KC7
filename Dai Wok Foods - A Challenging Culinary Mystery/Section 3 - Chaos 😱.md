# Section 3: Chaos 😱

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

---

## Question 1

A law enforcement agency warned Dai Wok Foods that they may been targeted by a threat actor. This coincides with a lot of computers at different restaurants sites being locked out recently. The agency said the threat actor may have sent the malware with the file name "`Local_County_Updates.xlsx`". When was the first time this file was seen?

### KQL Query

```kql
Email
| where link contains "Local_County_Updates.xlsx"
| project timestamp
```

### Answer

`2023-05-12T09:22:48Z`

---

## Question 2

Who was the email sender?

### KQL Query

```kql
Email
| where link contains "Local_County_Updates.xlsx"
| where timestamp == "2023-05-12T09:22:48.000Z"
| project sender
```

### Answer

`restaurant@verizon.com`

---

## Question 3

Who was the `reply_to` email address?

### KQL Query

```kql
Email
| where link contains "Local_County_Updates.xlsx"
| where timestamp == "2023-05-12T09:22:48.000Z"
| project reply_to
```

### Answer

`miguel_waters@hoisumsupplies.com`

---

## Question 4

Oh no! Looks like one of our partners may have been affected. Let's investigate our employees and see if they may have clicked on the link. When did the first employee click on the link?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "Local_County_Updates"
```

### Notes

- Take the earlier timestamp from the returned results.

### Answer

`2023-05-12T10:00:55Z`

---

## Question 5

What's the role of the employee who clicked on the link?

### KQL Query

```kql
Employees
| where ip_addr == "192.168.1.176"
| project role
```

### Answer

`Ingredient Procurement`

---

## Question 6

(ADVANCED) Investigate all of the domains and emails associated with the threat actor. When is the first time this threat actor sent an email to Dai Wok Foods?

### KQL Query

```kql
let bad_actors =
Email
| where link contains "Local_County_Updates.xlsx"
| distinct sender, reply_to;

let actors =
union
(bad_actors | project actor = sender),
(bad_actors | project actor = reply_to)
| distinct actor;

let doms =
Email
| where sender in (actors) or reply_to in (actors)
| extend dom = tostring(parse_url(link).Host)
| distinct dom;

Email
| extend link_dom = tostring(parse_url(link).Host)
| where link_dom in (doms)
```

### Answer

`2023-05-06T08:33:13Z`

---

## Question 7

(ADVANCED) How many unique domains are associated with this threat actor?

### KQL Query

```kql
let bad_actors =
Email
| where link contains "Local_County_Updates.xlsx"
| distinct sender, reply_to;

let actors =
union
(bad_actors | project actor = sender),
(bad_actors | project actor = reply_to)
| distinct actor;

let doms =
Email
| where sender in (actors) or reply_to in (actors)
| extend dom = tostring(parse_url(link).Host)
| distinct dom;

Email
| extend link_dom = tostring(parse_url(link).Host)
| where link_dom in (doms)
| distinct link_dom
```

### Answer

`3`

---

## Question 8

(ADVANCED) How many malware files placed by the threat actor are still present across all of the Dai Wok host machines?

### KQL Query

```kql
let bad_actors =
Email
| where link contains "Local_County_Updates.xlsx"
| distinct sender, reply_to;

let actors =
union
(bad_actors | project actor = sender),
(bad_actors | project actor = reply_to)
| distinct actor;

let doms =
Email
| where sender in (actors) or reply_to in (actors)
| extend dom = tostring(parse_url(link).Host)
| distinct dom;

let bad_files =
Email
| extend link_dom = tostring(parse_url(link).Host)
| where link_dom in (doms)
| extend paths = tostring(parse_url(link).Path)
| extend filename = tostring(parse_path(paths).Filename)
| distinct filename;

let bad_files_hosts =
FileCreationEvents
| where filename in (bad_files)
| distinct hostname;

let next_filesss =
FileCreationEvents
| where hostname in (bad_files_hosts)
| serialize
| extend next_file = next(filename)
| where filename in (bad_files)
| where next_file !in (bad_files)
| distinct next_file;

FileCreationEvents
| where filename in (next_filesss) or filename in (bad_files)
```

### Answer

`13`

---

## Question 9

(ADVANCED) Which threat actor is this publicly reported as?

### Notes

- Using Google, check the malware files identified during the investigation.
- The system is infected by **Bablock**.

### Answer

`Bablock`

---

## Question 10

(ADVANCED) What is the MITRE ID for the technique used by the threat actor to execute malware payloads?

### Notes

- Use Google to research the MITRE ATT&CK technique associated with Bablock and the observed execution-flow hijacking activity.

### Answer

`T1574.002`

---

## Question 11

(ADVANCED) What is the SHA256 hash of the file used for the technique found in Q10?

### Notes

- The file used to hijack the execution flow is `cy.exe`.
- Copy its SHA256 hash from the investigation results.

### Answer

`4874d336c5c7c2f558cfd5954655cacfc85bcfcb512a45fb0ff461ce9c38b86d`

---

## Question 12

(ADVANCED) What legitimate process is being used by the threat actor from what you found for Q10?

### KQL Query

```kql
let bad_actors =
Email
| where link contains "Local_County_Updates.xlsx"
| distinct sender, reply_to;

let actors =
union
(bad_actors | project actor = sender),
(bad_actors | project actor = reply_to)
| distinct actor;

let doms =
Email
| where sender in (actors) or reply_to in (actors)
| extend dom = tostring(parse_url(link).Host)
| distinct dom;

let bad_files =
Email
| extend link_dom = tostring(parse_url(link).Host)
| where link_dom in (doms)
| extend paths = tostring(parse_url(link).Path)
| extend filename = tostring(parse_path(paths).Filename)
| distinct filename;

let bad_files_hosts =
FileCreationEvents
| where filename in (bad_files)
| distinct hostname;

let next_filesss =
FileCreationEvents
| where hostname in (bad_files_hosts)
| serialize
| extend next_file = next(filename)
| where filename in (bad_files)
| where next_file !in (bad_files)
| distinct next_file;

ProcessEvents
| where process_commandline has_any (next_filesss)
```

### Notes

- Review the `process_name` column in the results.
- A single legitimate Windows process is observed.

### Answer

`notepad.exe`

---

## Question 13

(ADVANCED) What file was used by the threat actor for Q10 but is no longer found on any of the host machines?

### Notes

- Review the results from Question 12.
- A DLL file appears in the `process_commandline`.
- The file is no longer present on any host.

### Answer

`winutils.dll`

---

## Question 14

What type of attack is this? What will likely happen soon?

### Notes

- Multiple hosts are infected.
- Executable files are being used throughout the environment.
- The activity is consistent with a ransomware attack.

### Answer

`ransomware`

---

## Question 15

(ADVANCED) What command line argument did they use to delete things on a host machine?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "delete"
```

### Answer

`vssadmin.exe delete shadows /All /Quiet`

---