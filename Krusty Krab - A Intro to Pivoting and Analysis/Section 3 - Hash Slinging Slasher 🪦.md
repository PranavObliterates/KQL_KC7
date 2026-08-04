# Section 3: Hash Slinging Slasher 🪦

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

---

## Question 1

How many employees were sent emails with a link to the domain `nightshift.com`?

### KQL Query

```kql
Email
| where link contains "nightshift.com"
| distinct recipient
```

### Answer

`3`

---

## Question 2

What was the subject line used for the emails from Question 1?

### KQL Query

```kql
Email
| where link contains "nightshift.com"
| distinct subject
```

### Answer

`[EXTERNAL] FW: Krabby Patty Worm Detected`

---

## Question 3

One of the three emails from Question 1 had a `CLEAN` verdict.

Who was the recipient of this email?

### KQL Query

```kql
Email
| where link contains "nightshift.com"
| where verdict == "CLEAN"
| project recipient
```

### Answer

`brad_kasky@krustykrab.com`

---

## Question 4

The domain `nightshift.com` resolved to multiple IP addresses.

Which IP did it resolve to first?

### KQL Query

```kql
PassiveDns
| where domain == "nightshift.com"
```

Review the records chronologically and identify the earliest resolution.

### Answer

`197.254.115.67`

---

## Question 5

Look back at the email address found in Question 3.

What is this employee's role?

### KQL Query

```kql
let emp_email =
Email
| where link contains "nightshift.com"
| where verdict == "CLEAN"
| project recipient;

Employees
| where email_addr in (emp_email)
| project role
```

### Answer

`Vendor Manager`

---

## Question 6

What is the IP address of the employee found in Question 3?

### KQL Query

```kql
let emp_email =
Email
| where link contains "nightshift.com"
| where verdict == "CLEAN"
| project recipient;

Employees
| where email_addr in (emp_email)
| project ip_addr
```

### Answer

`192.168.0.204`

---

## Question 7

Look back at the IP address found in Question 6.

What time did this employee click the link to `nightshift.com`?

### KQL Query

```kql
OutboundNetworkEvents
| where src_ip == "192.168.0.204"
| where url contains "nightshift.com"
| project timestamp
```

### Answer

`2023-03-02T08:49:23Z`

---

## Question 8

Look back at the IP address found in Question 6.

Who does this IP address belong to?

### KQL Query

```kql
let emp_email =
Email
| where link contains "nightshift.com"
| where verdict == "CLEAN"
| project recipient;

Employees
| where email_addr in (emp_email)
| project name
```

### Answer

`Brad Kasky`

---

## Question 9

Let's do some more investigation of the first employee found in Questions 3, 5, and 6.

What is this employee's username?

### KQL Query

```kql
let emp_email =
Email
| where link contains "nightshift.com"
| where verdict == "CLEAN"
| project recipient;

Employees
| where email_addr in (emp_email)
| project username
```

### Answer

`brkasky`

---

## Question 10

Let's review authentication activity for the user found in Question 9.

Two user agents were used for logins to this user's account.

Which user agent was used most often? Include only the last part of the user agent.

### KQL Query

```kql
AuthenticationEvents
| where username == "brkasky"
| summarize count() by user_agent
```

Compare the counts for each `user_agent`. The most frequently observed user agent is the answer.

### Answer

`Firefox/51.0`

---

## Question 11

Look back at the timestamp found in Question 7, when the employee clicked the suspicious link.

What user agent is seen around this time, approximately one day later?

### KQL Query

```kql
AuthenticationEvents
| where username == "brkasky"
| summarize count() by user_agent
```

The unusual user agent appears only once. Reviewing its associated authentication activity shows that it occurs approximately one day after the suspicious link click identified in Question 7.

### Answer

`Firefox/3.6.20`

---

## Question 12

Which IP address did the actors use to try to log into Brad Kasky's account?

### KQL Query

First, identify Brad Kasky's legitimate employee IP:

```kql
let brad_ip =
Employees
| where username == "brkasky"
| project ip_addr;

AuthenticationEvents
| where username == "brkasky"
| where src_ip !in (brad_ip)
| summarize count() by src_ip
```

This reveals external IP addresses attempting to authenticate to the account.

To investigate the suspicious IP further, pivot into Passive DNS:

```kql
PassiveDns
| where ip == "187.111.81.175"
```

The IP resolves to several domains following a similar suspicious naming theme, strengthening the indication that it belongs to attacker infrastructure.

### Answer

`187.111.81.175`

---

## Question 13

What was the result of the login attempt from the actor IP found in Question 12?

### KQL Query

```kql
let brad_ip =
Employees
| where username == "brkasky"
| project ip_addr;

AuthenticationEvents
| where username == "brkasky"
| where src_ip == "187.111.81.175"
| project result
```

### Answer

`Failed Login`

---

## Question 14

One other employee clicked a link to `nightshift.com`.

What is this employee's IP address?

This is not the employee whose IP address was found in Question 6.

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "nightshift.com"
| where src_ip != "192.168.0.204"
```

### Answer

`192.168.2.157`

---

## Question 15

What time did the employee from Question 14 click the link to `nightshift.com`?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "nightshift.com"
| where src_ip == "192.168.2.157"
| project timestamp
```

### Answer

`2023-03-02T09:01:48Z`

---

## Question 16

What is the username for the employee found in Question 14?

### KQL Query

```kql
Employees
| where ip_addr == "192.168.2.157"
| project username
```

### Answer

`maharber`

---

## Question 17

The employee found in Question 14 attempted to log in from one IP address.

What is that IP?

### KQL Query

```kql
AuthenticationEvents
| where username == "maharber"
| project src_ip
```

### Answer

`50.6.66.245`

---

## Question 18

How many total users logged in, or attempted to log in, from the IP found in Question 17?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "50.6.66.245"
```

Review the authentication records and their associated users.

### Answer

`3`

---

## Question 19

One employee logged in successfully from the IP found in Question 17.

What is this employee's username?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "50.6.66.245"
| where result == "Successful Login"
| project username
```

### Answer

`juhong`

---

## Question 20

What is the email address of the employee found in Question 19?

### KQL Query

```kql
let emp_user =
AuthenticationEvents
| where src_ip == "50.6.66.245"
| where result == "Successful Login"
| project username;

Employees
| where username in (emp_user)
| project email_addr
```

### Answer

`julie_hong@krustykrab.com`

---

## Question 21

Julie Hong received an email with almost the same subject line found in Question 2.

Who sent this email?

### KQL Query

```kql
Email
| where recipient == "julie_hong@krustykrab.com"
| where subject contains "Krabby Patty Worm Detected"
| project sender
```

### Answer

`nosferatu.hash@hotmail.com`

---

## Question 22

How many employees were targeted by the email found in Question 21?

### KQL Query

```kql
Email
| where sender == "nosferatu.hash@hotmail.com"
| distinct recipient
```

### Answer

`4`

---

## Question 23

The attacker email found in Question 22 used one domain in the links they sent.

What is this domain?

### KQL Query

```kql
Email
| where sender == "nosferatu.hash@hotmail.com"
| extend dom = tostring(parse_url(link).Host)
| distinct dom
```

### Answer

`scarynight.net`

---

## Question 24

The domain found in Question 23 resolves to the IP found in Question 17.

What time was this resolution captured in Passive DNS?

### KQL Query

```kql
PassiveDns
| where domain == "scarynight.net"
```

From the returned records, locate the entry where:

```text
IP: 50.6.66.245
```

The timestamp associated with this resolution is the answer.

### Answer

`2023-03-09T18:23:40Z`

---

## Question 25

The attackers exfiltrated data from the mailbox of the employee found in Question 19.

What time did this occur?

The exfiltration originated from the attacker IP found in Question 17.

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "50.6.66.245"
| where url contains "juhong"
```

Inspect the mailbox-related activity associated with Julie Hong's username.

### Answer

`2023-03-02T08:57:36Z`

---

## Question 26

What mailbox folder did the attackers exfiltrate data from?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "50.6.66.245"
| where url contains "juhong"
```

Inspect the URL from the exfiltration event. The mailbox folder is visible in the URL parameter:

```text
mailbox_folder=Deleted Mail
```

### Answer

`Deleted Mail`

---

## Question 27

The attackers likely started the reconnaissance phase of their attack on February 23 from the IP found in Question 17.

What did they search for on February 24th and March 11th?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "50.6.66.245"
```

Review the six returned events. The reconnaissance activity on February 24 and March 11 contains the same search query.

### Answer

`krabby patty`

---