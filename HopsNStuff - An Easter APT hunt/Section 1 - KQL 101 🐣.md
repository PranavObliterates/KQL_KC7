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

Welcome to HopsNStuff! 🥳

Today is your first day as a Junior Security Operations Center (SOC) Analyst with our company. Your primary job responsibility is to defend HopsNStuff and our employees from malicious cyber actors.

HopsNStuff is a brewery renowned for crafting the most delectable ginger beer around. But what truly sets us apart is our secret formula, passed down from generation to generation. Our expert brewmasters use only the finest ginger, combined with a blend of carefully selected ingredients, to create a taste that's truly one-of-a-kind.

Try it for yourself! Do a take 10 on all the other tables to see what kind of data they contain.

**Type "done" here when finished to earn your first 10 points!**

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

`923`

---

## Question 3

Each employee at HopsNStuff is assigned an IP address. Which employee has the IP address: `192.168.2.191`?

### KQL Query

```kql
Employees
| where ip_addr == "192.168.2.191"
```

### Answer

`John Clark`

---

## Question 4

How many emails did Simeon Kakpovi receive?

### KQL Query

```kql
let simeon_mail = 
Employees
| where name == "Simeon Kakpovi"
| project email_addr;
Email
| where recipient in (simeon_mail)
| count
```

### Answer

`32`

---

## Question 5

How many distinct senders were seen in the email logs from easterdelights.org?

### KQL Query

```kql
Email
| where sender endswith "easterdelights.org"
| distinct sender
```

### Answer

`1670`

---

## Question 6

How many unique URLs did “Arthur Raymond” visit?

### KQL Query

```kql
let arthur_ip = 
Employees
| where name has "Arthur Raymond"
| project ip_addr;
OutboundNetworkEvents
| where src_ip in (arthur_ip)
| distinct url
```

### Answer

`72`

---

## Question 7

How many domains in the PassiveDNS records contain the word “automation”? (hint: use the contains operator instead of has. If you get stuck, do a take 10 on the table to see what fields are available.)

### KQL Query

```kql
PassiveDns
| where domain contains "automation"
| distinct domain
```

### Answer

`34`

---

## Question 8

What IP addresses did the domain `automationpackages.com` resolve to (if there are more than one, enter any one of them)?

### KQL Query

```kql
PassiveDns
| where domain == "automationpackages.com"
| distinct ip
```

### Answer

`190.78.143.29`

---

## Question 9

How many unique URLs were browsed by employees named “Karen”?

### KQL Query

```kql
let karen_ips = 
Employees
| where name has "Karen"
| project ip_addr;
OutboundNetworkEvents
| where src_ip in (karen_ips)
| distinct url
```

### Answer

`154`

---