# Section 2: Just Keep Swimming 🐟

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

---

## Question 1

Your cybersecurity team has received multiple alerts about suspicious activity originating from the email address `nosferatu.hash@hotmail.com`. You've been asked to investigate. Let's see what we can learn!

How many emails were sent by `nosferatu.hash@hotmail.com`?

### KQL Query

```kql
Email
| where sender == "nosferatu.hash@hotmail.com"
```

### Answer

`4`

---

## Question 2

What is the subject of the emails sent by `nosferatu.hash@hotmail.com`?

### KQL Query

```kql
Email
| where sender == "nosferatu.hash@hotmail.com"
| project subject
```

### Answer

`[EXTERNAL] RE: Krabby Patty Worm Detected`

---

## Question 3

How many of the emails sent by `nosferatu.hash@hotmail.com` were marked as `SUSPICIOUS`?

### KQL Query

```kql
Email
| where sender == "nosferatu.hash@hotmail.com"
| where verdict == "SUSPICIOUS"
```

### Answer

`2`

---

## Question 4

It seems like this nosferatu wanted users to click on something in the email.

What domain was observed in the links sent by `nosferatu.hash@hotmail.com`?

### KQL Query

```kql
Email
| where sender == "nosferatu.hash@hotmail.com"
| distinct link
| extend dom = tostring(parse_url(link).Host)
| project dom
```

### Answer

`scarynight.net`

---

## Question 5

One of our other analysts found that there may be even more emails from this threat actor.

We can find these other emails by searching `nosferatu.hash@hotmail.com` in the `reply_to` field. One of these email addresses is `nosferatu@gmail.com`.

How many emails were sent by the email address `nosferatu@gmail.com`?

### KQL Query

```kql
Email
| where sender == "nosferatu@gmail.com"
```

### Answer

`7`

---

## Question 6

Who was the first person to receive an email from `nosferatu@gmail.com`? Enter their email address.

### KQL Query

```kql
Email
| where sender == "nosferatu@gmail.com"
| sort by timestamp asc
```

Use the `recipient` field of the first result.

### Answer

`james_jefferies@krustykrab.com`

---

## Question 7

What was the subject of the email that `james_jefferies@krustykrab.com` received from `nosferatu@gmail.com`?

### KQL Query

```kql
Email
| where sender == "nosferatu@gmail.com"
| sort by timestamp asc
```

Use the `subject` field of the first result.

### Answer

`[EXTERNAL] FW: Confidential Memo: Krusty Krab Under Attack`

---

## Question 8

It doesn't look like all the emails ended up in users' inboxes. Some of them were blocked.

How many of the emails sent by `nosferatu@gmail.com` were blocked?

### KQL Query

```kql
Email
| where sender == "nosferatu@gmail.com"
| where verdict == "BLOCKED"
```

### Answer

`2`

---

## Question 9

Threat actors often want users to act without thinking, and this actor doesn't seem any different. `nosferatu@gmail.com` sent some emails starting with `URGENT`.

What was the full subject of the urgent emails?

### KQL Query

```kql
Email
| where sender == "nosferatu@gmail.com"
| where subject contains "URGENT"
| distinct subject
```

### Answer

`[EXTERNAL] FW: URGENT: Krusty Krab Secret Recipe Leaked`

---

## Question 10

In Question 5, our other analyst had a good idea: Are there more emails we can find by looking at the `reply_to` field associated with `nosferatu@gmail.com`?

What other email addresses are in the `reply_to` field used by this actor?

### KQL Query

```kql
Email
| where sender == "nosferatu@gmail.com"
| distinct reply_to
```

### Answer

`graveyard@hotmail.com`

---

## Question 11

It looks like Julie Hong visited the link in one of the suspicious emails. The email contained a link to `scarynight.net`.

When did she click on the link?

### KQL Query

```kql
let julie_ip =
Employees
| where name has "Julie Hong"
| project ip_addr;

OutboundNetworkEvents
| where src_ip in (julie_ip)
| where url contains "scarynight.net"
```

### Answer

`2023-03-01T09:36:22Z`

---

## Question 12

Julie wasn't the only employee who clicked one of these links.

What is the IP address of the first person who clicked on a link containing the domain `scarynight.net`?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "scarynight.net"
```

Check the earliest event and its `src_ip`.

### Answer

`192.168.1.243`

---

## Question 13

Who does the IP address from Question 12 belong to?

### KQL Query

```kql
Employees
| where ip_addr == "192.168.1.243"
```

### Answer

`Toni Jones`

---

## Question 14

Another analyst found that there appear to be multiple malicious domains. Some employees clicked links for `sleeve-dark.net`.

How many people clicked on the link with the domain `sleeve-dark.net`?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "sleeve-dark.net"
```

### Answer

`2`

---

## Question 15

Knowing that there are multiple domains, we may want to see if there are any more websites using the same theme.

Let's look for more websites with the word `sleeve` in the domain.

How many unique employees clicked on links containing the word `sleeve`?

### KQL Query

```kql
let unique_emp_ips_sleeve =
OutboundNetworkEvents
| where url contains "sleeve"
| distinct src_ip;

Employees
| where ip_addr in (unique_emp_ips_sleeve)
| distinct name
```

### Answer

`7`

---

## Question 16

We saw the domain `scarynight.net` earlier. Perhaps there are more domains with that theme too.

How many unique employees clicked on links containing the word `night`?

### KQL Query

```kql
let unique_emp_ips_night =
OutboundNetworkEvents
| where url contains "night"
| distinct src_ip;

Employees
| where ip_addr in (unique_emp_ips_night)
| distinct name
```

### Answer

`38`

---

## Question 17

What about the word `midnight`?

How many unique employees clicked on links containing the word `midnight`?

### KQL Query

```kql
let unique_emp_ips_midnight =
OutboundNetworkEvents
| where url contains "midnight"
| distinct src_ip;

Employees
| where ip_addr in (unique_emp_ips_midnight)
| distinct name
```

### Answer

`3`

---

## Question 18

We don't know whether all of these results are related. One may be a legitimate music website.

One way to identify more suspicious infrastructure is by looking at the Top-Level Domain (TLD). One of the results containing `midnight` uses a less common TLD.

What is the full domain using the word `midnight` with the less common TLD?

### KQL Query

```kql
OutboundNetworkEvents
| where url contains "midnight"
| extend doms = tostring(parse_url(url).Host)
| distinct doms
```

Review the returned domains and identify the one using the uncommon TLD.

### Answer

`midnighttech.dev`

---

## Question 19

Another analyst determined that several of these links appear to lead to credential harvesters. A few of the domains resolve to the IP address `54.17.157.246`.

Let's investigate whether employees were tricked into entering their credentials.

How many login attempts were there from `54.17.157.246`?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "54.17.157.246"
```

### Answer

`3`

---

## Question 20

One of our end users, Zenaida Warren, reported that she clicked a malicious link.

When did IP `54.17.157.246` attempt to log into Zenaida Warren's account?

### KQL Query

```kql
let zenaida_user =
Employees
| where name has "Zenaida Warren"
| project username;

AuthenticationEvents
| where src_ip == "54.17.157.246"
| where username in (zenaida_user)
| project timestamp
```

### Answer

`2023-03-02T02:17:32Z`

---

## Question 21

What was the result of the attempted login to Zenaida Warren's account from IP `54.17.157.246`?

### KQL Query

```kql
let zenaida_user =
Employees
| where name has "Zenaida Warren"
| project username;

AuthenticationEvents
| where src_ip == "54.17.157.246"
| where username in (zenaida_user)
| project result
```

### Answer

`Failed Login`

---

## Question 22

Another analyst identified several other suspicious logins. One of them originated from IP address `136.61.241.165`.

Whose account did IP `136.61.241.165` first log into?

### KQL Query

```kql
AuthenticationEvents
| where src_ip == "136.61.241.165"
| sort by timestamp asc
```

The first event identifies the username `timorrow`.

```kql
Employees
| where username == "timorrow"
```

### Answer

`Tina Morrow`

---

## Question 23

The IP wasn't only used to log into accounts. It was also probing the Krusty Krab website.

How many requests did IP `136.61.241.165` make to the Krusty Krab website?

### KQL Query

```kql
InboundNetworkEvents
| where url contains "krustykrab.com"
| where src_ip == "136.61.241.165"
```

### Answer

`3`

---

## Question 24

It looks like the actor was searching for something specific on the website.

What job-related terms did IP `136.61.241.165` search for on the Krusty Krab website?

### KQL Query

```kql
InboundNetworkEvents
| where url contains "krustykrab.com"
| where src_ip == "136.61.241.165"
```

Inspect the URL query and replace `%20` with spaces.

### Answer

`fry cook listings`

---

## Question 25

Looking at the other events, it appears that the actor using IP `136.61.241.165` downloaded a ZIP file from Tina Morrow's account.

What was the name of the ZIP file?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "136.61.241.165"
| where url contains ".zip"
```

Inspect the URL containing Tina Morrow's username.

### Answer

`important.zip`

---

## Question 26

Was there similar activity from the `54.17.157.246` address?

There was. It looks like the attacker downloaded a file from Hector Duncan's mail account.

What was the name of the file?

### KQL Query

```kql
let hector_user =
Employees
| where name has "Hector Duncan"
| project username;

InboundNetworkEvents
| where src_ip == "54.17.157.246"
| where url has_any (hector_user)
```

### Answer

`email.7z`

---

## Question 27

In Question 20, another analyst told us that some domains resolved to `54.17.157.246`. Let's verify that ourselves.

How many unique domains resolved to the IP `54.17.157.246`?

### KQL Query

```kql
PassiveDns
| where ip == "54.17.157.246"
| distinct domain
```

### Answer

`8`

---

## Question 28

One of those domains looks similar to infrastructure we saw earlier: `scarysleeve.org`.

How many other domains shared the same IP addresses with the domain `scarysleeve.org`?

### KQL Query

First, retrieve all IP addresses associated with `scarysleeve.org`, then pivot back into `PassiveDns` using those IPs:

```kql
let scarysleeve_ips =
PassiveDns
| where domain == "scarysleeve.org"
| distinct ip;

PassiveDns
| where ip in (scarysleeve_ips)
| distinct domain
| where domain != "scarysleeve.org"
```

### Answer

`13`

---