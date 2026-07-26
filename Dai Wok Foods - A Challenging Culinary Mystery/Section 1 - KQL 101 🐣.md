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
- [Question 10](#question-10)

---

## Question 1

Try it for yourself! Do a `take 10` on all the other tables to see what kind of data they contain.

Type `done` when you are finished.

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

`1111`

---

## Question 3

Each employee at Dai Wok Foods is assigned an IP address.

Which employee has the IP address `192.168.2.191`?

### KQL Query

```kql
Employees
| where ip_addr == "192.168.2.191"
```

### Answer

`Wayne Rydberg`

---

## Question 4

How many emails did Stuart Carter receive?

### KQL Query

```kql
let carter_mail =
Employees
| where name has "Stuart Carter"
| distinct email_addr;

Email
| where recipient in (carter_mail)
```

### Answer

`38`

---

## Question 5

How many distinct senders were seen in the email logs from `siusamteas.com`?

### KQL Query

```kql
Email
| where sender endswith "siusamteas.com"
| distinct sender
```

### Answer

`1546`

---

## Question 6

How many unique URLs did **Mary Davis** visit?

### KQL Query

```kql
let mary_davis_ip =
Employees
| where name == "Mary Davis"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (mary_davis_ip)
| distinct url
```

### Answer

`66`

---

## Question 7

How many domains in the `PassiveDns` records contain the word **"legal"**?

### KQL Query

```kql
PassiveDns
| where domain has "legal"
```

### Answer

`89`

---

## Question 8

What IPs did the domain `foodadministration-legal-services.com` resolve to (enter any one of them)?

### KQL Query

```kql
PassiveDns
| where domain == "foodadministration-legal-services.com"
| distinct ip
```

### Notes

- The query returns five IP addresses.
- Any one of them is accepted.

### Answer

`131.162.160.193`

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

`221`

---

## Question 10

Who is the Chief Executive Officer of Dai Wok Foods?

### KQL Query

```kql
Employees
| where role == "Chief Executive Officer"
```

### Answer

`Abby Zelda`

---