# Section 2: 🌲 Forest Blizzard ❄️

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

---

## Question 1

Let's take a look at our security alerts. It looks like there was a file that was quarantined on October 2, 2023.

How many files with this filename is present on Scholomance hosts?

### KQL Query (Identify Quarantined File)

```kql
SecurityAlerts
| where timestamp >= datetime(2023-10-02T00:00:00.000Z)
| where description contains "quarantine"
```

### Notes

- Only one file was quarantined on **2023-10-02**.
- The filename is **details.zip**.

### KQL Query (Find File on Hosts)

```kql
FileCreationEvents
| where filename == "details.zip"
```

### Answer

`15`

---

## Question 2

How many roles were impacted with this file?

### KQL Query

```kql
FileCreationEvents
| where filename == "details.zip"
| lookup Employees on $left.username == $right.username
| distinct role
```

### Answer

`9`

---

## Question 3

Let's pivot to emails.

Identify all of the unique senders for this file.

How many unique domains did they use to serve this file?

### KQL Query

```kql
Email
| where link contains "details.zip"
| extend dom = tostring(parse_url(link).Host)
| distinct dom
```

### Answer

`5`

---

## Question 4

Look for all the files this threat actor served.

How many total emails were sent by this threat actor containing potentially malicious files?

### KQL Query

```kql
let bad_sender =
Email
| where link contains "details.zip"
| distinct sender;

Email
| where sender in (bad_sender)
```

### Answer

`69`

---

## Question 5

How many of these files were present on hosts?

### KQL Query

```kql
let bad_sender =
Email
| where link contains "details.zip"
| distinct sender;

let affected_reci =
Email
| where sender in (bad_sender)
| distinct recipient;

let hosts =
Employees
| where email_addr in (affected_reci)
| distinct hostname;

FileCreationEvents
| where hostname in (hosts)
| where filename in ("details.zip", "IOC_30_08.rar", "photo.zip")
```

### Answer

`66`

---

## Question 6

Let's look for impact.

How many total job roles were targeted?

### KQL Query

```kql
let bad_sender =
Email
| where link contains "details.zip"
| distinct sender;

let affected_reci =
Email
| where sender in (bad_sender)
| distinct recipient;

let hosts =
Employees
| where email_addr in (affected_reci)
| distinct hostname;

let users =
FileCreationEvents
| where hostname in (hosts)
| where filename in ("details.zip", "IOC_30_08.rar", "photo.zip")
| distinct username;

Employees
| where username in (users)
| distinct role
```

### Answer

`12`

---

## Question 7

Let's start investigating what happens after these emails were sent & downloaded onto these hosts.

The threat actor is staging files somewhere.

What is the full path to the directory?

### KQL Query (Identify Affected Users)

```kql
let bad_sender =
Email
| where link contains "details.zip"
| distinct sender;

let affected_reci =
Email
| where sender in (bad_sender)
| distinct recipient;

let hosts =
Employees
| where email_addr in (affected_reci)
| distinct hostname;

FileCreationEvents
| where hostname in (hosts)
| where filename in ("details.zip", "IOC_30_08.rar", "photo.zip")
| distinct username
```

### KQL Query (Review File Activity)

```kql
FileCreationEvents
| where username == "almcfadden"
```

### KQL Query (Confirm Across Another Host)

```kql
FileCreationEvents
| where username == "mahall"
```

### Notes

- Review file activity after `details.zip`, `IOC_30_08.rar`, or `photo.zip` are created.
- Multiple suspicious files with extensions such as `.cmd`, `.vbs`, and `.css` are staged in the same directory.

### Answer

`C:\ProgramData`

---

## Question 8

It may be worth it to start conducting open source intelligence on these files.

Some of these files are tied to the previous section.

What other group, named by Mandiant, are these other files associated with?

### Notes

- Perform OSINT using the observed filenames and extensions (`.cmd`, `.vbs`, `.css`).
- Mandiant attributes these artifacts to the following threat group.

### Answer

`APT28`

---

## Question 9

Now that you have some information on this threat, what filename (minus the extension) is used for collecting credentials?

### Notes

- Two files share the same base filename with `.vbs` and `.cmd` extensions.
- Remove the extension before submitting.

### Answer

`dc529177-39b4-4828-8c66-79fe35145d07`

---

## Question 10

It looks like they may have dumped something from a native Windows database and saved it somewhere.

What's the name of this file?

### KQL Query

```kql
ProcessEvents
| where username == "mahall"
| where timestamp >= datetime(2023-10-26T00:00:00.000Z)
```

### Notes

- Review the process activity manually.
- One command saves a Windows database locally.

### Answer

`software.save`

---

## Question 11

What's being used by the threat actor as a bootloader?

### KQL Query

```kql
ProcessEvents
| where username == "mahall"
```

### Notes

- Review events following execution of the `.cmd`, `.vbs`, and `.css` files.
- `msedge.exe` consistently appears immediately after system startup.

### Answer

`msedge.exe`

---

## Question 12

What GUID is being used in conjunction with this?

### KQL Query

```kql
ProcessEvents
| where username == "mahall"
| where timestamp >= datetime(2023-10-26T00:00:00.000Z)
```

### Notes

- Review events referencing `msedge.exe` and identify the associated GUID.

### Answer

`aaccd6de-ce95-4fb2-b2c1-2d7ca08661a3`

---

## Question 13

Investigate likely data exfiltration.

What filename were they using to stage the data?

### KQL Query

```kql
ProcessEvents
| where username == "mahall"
| where timestamp >= datetime(2023-10-26T00:00:00.000Z)
| where process_commandline contains ".zip"
```

### Answer

`protect.zip`

---

## Question 14

What's the destination where the data was likely being transferred to?

### KQL Query

```kql
ProcessEvents
| where username == "mahall"
| where timestamp >= datetime(2023-10-26T00:00:00.000Z)
```

### Notes

- Review the event immediately following the archive creation to identify the upload destination.

### Answer

`https://webhook.site/dc529177-39b4-4828-8c66-79fe35145d07`

---

## Question 15

There were some things missing or re-configured on these hosts.

What did the threat actor do for defense evasion? What did they disable?

### KQL Query

```kql
ProcessEvents
| where username == "mahall"
```

### Notes

- Search for commands relating to disabling or deleting security features.
- The attacker disabled **LSA** as a defense evasion technique.

### Answer

`LSA`

---

## Question 16

Both of these threat actor groups are part of which specific agency from their country of origin?

### Notes

- Perform OSINT on **APT28** and the related threat group.
- Both are associated with Russia's military intelligence agency.

### Answer

`GRU`

---