# Section 5: Y'all Too Good

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

---

## Question 1

Employee lushearer had their account compromised on 2023-03-08. From what IP address did this occur?

### KQL Query

```kql
AuthenticationEvents
| where username == "lushearer"
| where timestamp >= (datetime(2023-03-08T00:00:00Z))
```

### Notes

- Check the first and only log on 8 March.

### Answer

`54.17.157.246`

---

## Question 2

How many total employees were compromised (successfully or unsuccessfully) from the IP you found in Question 1?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "54.17.157.246"
```

### Answer

`3`

---

## Question 3

What subject line was used by the threat actor identified in Questions 1 and 2 to target Hector Duncan?

### KQL Query

```kql
let doms =
PassiveDns
| where ip == "54.17.157.246"
| distinct domain;

Email
| where link has_any (doms)
| where recipient == "hector_duncan@krustykrab.com"
```

### Answer

`[EXTERNAL] IMPORTANT: Krabby Patty Security Alert`

---

## Question 4

What time was the first user targeted using the subject line from Question 3?

### KQL Query

```kql
Email
| where subject == "[EXTERNAL] IMPORTANT: Krabby Patty Security Alert"
```

### Answer

`2023-03-06T03:59:40Z`

---

## Question 5

Which sender address associated with this actor targeted the most users?

### KQL Query

```kql
let bad_replyto =
Email
| where subject == "[EXTERNAL] IMPORTANT: Krabby Patty Security Alert"
| distinct reply_to;

let bad_sender =
Email
| where subject == "[EXTERNAL] IMPORTANT: Krabby Patty Security Alert"
| distinct sender;

Email
| where sender in (bad_replyto) or sender in (bad_sender)
| summarize count() by sender
| sort by count_ desc
```

### Answer

`slasher.graveyard@hotmail.com`

---

## Question 6

The attacker seems to have a lot of email addresses! We found emails with a similar subject sent from `legal@gmail.com`.

Which subject line was used by this address to target the fewest number of users?

### KQL Query

```kql
Email
| where sender == "legal@gmail.com"
| summarize count() by subject
| sort by count_ asc
```

### Answer

`[EXTERNAL] RE: Imagine what you could do with the Krusty Krab recipe...`

---

## Question 7

We previously observed data exfiltration from chanderson's device in section 4. The domain in the email we just found (question 6) appears familiar. The domain was also used in exfiltration!

What C2 domain was used in the URL in the email and exfiltration?

### KQL Query

```kql
Email
| where sender == "legal@gmail.com"
| where subject == "[EXTERNAL] RE: Imagine what you could do with the Krusty Krab recipe..."
| extend c2dom = tostring(parse_url(link).Host)
| project c2dom
```

### Answer

`computer-wife-formula.net`

---

## Question 8

What is the SHA256 of the file connecting to the C2 that was dropped on chanderson's device?

### KQL Query

```kql
FileCreationEvents
| where username == "chanderson"
```

### Notes

- The familiar file is `krabbypatty.exe`.

### Answer

`e3970346ff7fcc3665f027d7f221968087f3c42705f5799fbc1d2811ab1ca4ea`

---

## Question 9

What email address was used to target chanderson?

### KQL Query

```kql
Email
| where sender == "legal.human_resources@yandex.com"
| lookup Employees on $left.recipient == $right.email_addr
| distinct name
| count
```

### Answer

`legal.human_resources@yandex.com`

---

## Question 10

How many employees were targeted using the email address identified in Question 9?

### KQL Query

```kql
Email
| where sender == "legal.human_resources@yandex.com"
| lookup Employees on $left.recipient == $right.email_addr
| distinct name
| count
```

### Answer

`12`

---

## Question 11

An alert was sent on 2023-03-20 for a suspicious file. What is the name of the dropper file that was used to infect this device?

### KQL Query

```kql
SecurityAlerts
| where timestamp >= datetime(2023-03-20)
```

### Notes

- The infected hostname is `CJMB-DESKTOP`.
- The malicious file is `krabbypatty.exe`.

### Answer

`Jellyfish_Guide.pptx`

---

## Question 12

What time did the user who was targeted in Question 11 click on the link to download the dropper?

### KQL Query

```kql
OutboundNetworkEvents
| lookup Employees on $left.src_ip == $right.ip_addr
| where hostname == "CJMB-DESKTOP"
| where url contains "Jellyfish_Guide"
| project timestamp
```

### Answer

`2023-03-20T08:38:47Z`

---

## Question 13

User lecostain had data exfiltrated from their mailbox on the 15th. What sender email address was used by the attacker to target them?

### KQL Query

```kql
let leco_email =
Employees
| where username == "lecostain"
| project email_addr;

Email
| where recipient in (leco_email)
| where timestamp <= datetime(2023-03-15)
| where sender !contains "krustykrab"
```

### Answer

`nosferatu@gmail.com`

---