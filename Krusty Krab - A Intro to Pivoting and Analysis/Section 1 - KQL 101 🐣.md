# Section 1: KQL 101 🐣

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

---

## Question 1

The Krusty Krab is a mid-size fast food chain serving the greater Bikini Bottom metropolitan area.

The Krusty Krab is best known for its delectable Krabby Patties™, kelp shakes, and sea dogs. Because of its wild success, some of the Krusty Krab’s competitors would benefit from stealing its secret formula and reproducing it themselves. Of note, the Chum Bucket—a minor competitor—has been less than ethical in its attempts to infiltrate the Bikini Bottom patty market.

Your job is to defend the Krusty Krab and its employees from malicious cyber actors looking to steal the secret formula.

If you have already completed the KQL 101 section on other games, feel free to use the skip button to fast forward. You will still get credit for completing the questions.

Do a `take 10` on all the other tables to see what kind of data they contain.

Type `done` to get credit for this question.

### Answer

`done`

---

## Question 2

How many employees are in the company?

### KQL Query

```kql
Employees
| count
```

### Answer

`675`

---

## Question 3

Each employee at Krusty Krab is assigned an IP address.

Which employee has the IP address `192.168.1.191`?

### KQL Query

```kql
Employees
| where ip_addr == "192.168.1.191"
```

### Answer

`Florence Holliday`

---

## Question 4

How many emails did Hector Duncan receive?

### KQL Query

```kql
let hector_mail =
Employees
| where name has "Hector Duncan"
| distinct email_addr;

Email
| where recipient in (hector_mail)
```

### Answer

`15`

---

## Question 5

How many distinct senders were seen in the email logs from `bikini-bottom-fish.com`?

### KQL Query

```kql
Email
| where sender endswith "@bikini-bottom-fish.com"
| distinct sender
```

### Answer

`659`

---

## Question 6

How many unique websites did Christopher Lynch visit?

### KQL Query

```kql
let chris_ip =
Employees
| where name has "Christopher Lynch"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (chris_ip)
| distinct url
```

### Answer

`65`

---

## Question 7

How many domains in the `PassiveDns` records contain the word **"scary"**?

### KQL Query

```kql
PassiveDns
| where domain contains "scary"
| distinct domain
```

### Answer

`20`

---

## Question 8

What IP did the domain `scarynight.com` resolve to?

### KQL Query

```kql
PassiveDns
| where domain == "scarynight.com"
```

### Answer

`198.174.181.37`

---

## Question 9

How many unique URLs were browsed by employees named **Karen**?

### KQL Query

```kql
let karen_ips =
Employees
| where name has "Karen"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (karen_ips)
| distinct url
```

### Answer

`113`

---