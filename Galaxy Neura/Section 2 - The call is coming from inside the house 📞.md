# Section 2: The call is coming from inside the house 📞

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

---

## Question 1

Find the email addresses for the CEO, CFO and CTO.

What is the subject of the email all three of them received?

### KQL Query

```kql
let ceo_cto_cfo_mail =
Employees
| where role in ("CFO", "CEO", "CTO")
| project email_addr;

Email
| where recipient in (ceo_cto_cfo_mail)
| summarize count() by subject
```

### Notes

- Identify the subject that was sent to all three executives.

### Answer

`Woopsie, the code for your secret chip is gone. Pay up if you want it back 😘`

---

## Question 2

Hu-ho, could this be the threat actor the researcher was describing?

Let's see…

Who sent the email?

### KQL Query

```kql
let ceo_cto_cfo_mail =
Employees
| where role in ("CFO", "CEO", "CTO")
| project email_addr;

Email
| where recipient in (ceo_cto_cfo_mail)
| where subject == "Woopsie, the code for your secret chip is gone. Pay up if you want it back 😘 "
| distinct sender
```

### Answer

`jean_song@galaxyneura.tech`

---

## Question 3

But, wait! Look at that domain. It's coming from *inside* the company! This behaviour was not mentioned by the researcher 🤔

Let's learn more about that Jean Song.

What is their role?

### KQL Query

```kql
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project role
```

### Answer

`Freelance Software Engineer`

---

## Question 4

When did Jean Song start working for Galaxy Neura? (format: yyyy-mm-dd)

### KQL Query

```kql
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project hire_date
```

### Answer

`2025-02-10`

---

## Question 5

So Jean Song is a remote worker, recently hired. Something tickles at the back of your mind. Something that wants to be remembered, something that would push you on the right track. Was it something you heard or read…? Definitely not at that conference though.

[uhhhh](hxxps://media1[.]giphy[.]com/media/v1.Y2lkPTc5MGI3NjExeHJsaTBwN3g0Ym04aWVtMzZwcHM1OXp1MWY1MmptNG8yYmRxYW9kdyZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/Ex2W18L1l1JQHsrNYH/giphy.gif)

Anyway, there are only two options here: either Jean has been compromised and the threat actor is using their account, or Jean *is* the threat actor. Let's see if anything suspicious is happening with their login.

How many IP addresses are used to authenticate as Jean?

### KQL Query

```kql
let jean_user =
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project username;

AuthenticationEvents
| where username in (jean_user)
| distinct src_ip
```

### Answer

`2`

---

## Question 6

That's a non-suspicious amount of IPs. Most people will connect from at least two IPs depending on their setup, or if they're on-site or travelling.

That might mean Jean *is* a threat actor.

You should look at their machine, see if anything is afoot. Let's work backwards to start of with. The email they sent mentions some code has been deleted, code they had access to thanks to their job role…

Which github repository did Jean delete?

### KQL Query

```kql
ProcessEvents
| where hostname == "UIWO-LAPTOP"
| where process_commandline contains "git"
```

### Notes

- Review the Git activity on Jean's laptop.
- A `git clone` command reveals the repository associated with the Galaxy Neura project.
- Since the repository was cloned locally, the investigation indicates that Jean had a copy of the repository.

### Answer

`super-secret-chip-project`

---

## Question 7

Oh wow, they did not delete any random repo, they picked a very important one. One that they were sure they'd be able to ask a hefty sum for…

Which means they must have a copy of it.

What's the name of the github account they cloned the repository to?

### KQL Query

```kql
ProcessEvents
| where hostname == "UIWO-LAPTOP"
| where process_commandline contains "git"
```

### Notes

- Review the Git commands for a `git push`.
- The command references the repository `stolen-super-secret-chip-project`.
- The username from the GitHub URL identifies the account.

### Answer

`song-of-war`

---

## Question 8

You know Jean could not have stumbled upon that secret repo by chance. They must have done some research beforehand. Galaxy Neura uses the subdomain `devteam` to host all their code development documentations. As a newcomer, Jean would have been directed to it…

[thatway](hxxps://media0[.]giphy[.]com/media/v1.Y2lkPTc5MGI3NjExNjluOWcyazdlejZ5a3pzdWFvdWtxbzJ4OXMydnZhc3k3eG9scDVkZSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/emLs5klEWTKlSVeexj/giphy.gif)

It looks like a few searches have been done on that subdomain.

Which search query shows Jean was getting frustrated? (only enter the search terms, replace the + by spaces)

### KQL Query

```kql
InboundNetworkEvents
| where url contains "devteam"
| extend paths = tostring(parse_url(url).Path)
| extend cleaned = replace_string(paths, "+", " ")
```

### Notes

- Review the searches performed against the `devteam` subdomain.
- One query appears to show Jean becoming frustrated while searching for interesting projects.

### Answer

`top secret projects come on you gotta gimme something interesting`

---

## Question 9

You know Jean is the source of this browsing, because the user_agent is theirs, and one of the IP addresses matches the second one in the Authentication records.

It's probably time to take a closer look at those IP addresses. All three of them.

Which domain that does not start with an "f" is linked to those IP addresses?

### KQL Query

```kql
let jean_user =
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project username;

let bad_ips =
AuthenticationEvents
| where username in (jean_user)
| distinct src_ip;

let more_bad_ip =
InboundNetworkEvents
| where url == "https://devteam.galaxyneura.tech/search=top+secret+projects+come+on+you+gotta+gimme+something+interesting" or url == "https://devteam.galaxyneura.tech/onboarding"
| project src_ip;

PassiveDns
| where ip in (bad_ips) or ip in (more_bad_ip)
| where domain !startswith "f"
```

### Answer

`hireadev.today`

---

## Question 10

There is one more IP address linked to those domains, what is it?

### KQL Query

```kql
let jean_user =
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project username;

let bad_ips =
AuthenticationEvents
| where username in (jean_user)
| distinct src_ip;

let more_bad_ip =
InboundNetworkEvents
| where url == "https://devteam.galaxyneura.tech/search=top+secret+projects+come+on+you+gotta+gimme+something+interesting" or url == "https://devteam.galaxyneura.tech/onboarding"
| project src_ip;

let bad_doms =
PassiveDns
| where ip in (bad_ips) or ip in (more_bad_ip)
| distinct domain;

PassiveDns
| where domain in (bad_doms)
| distinct ip
```

### Answer

`70.39.103.3`

---

## Question 11

Let's look at any prior browsing on the company's network done by those IP addresses you found.

On what day did the previous browsing happen? (format: yyyy-mm-dd)

### KQL Query

```kql
let jean_user =
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project username;

let bad_ips =
AuthenticationEvents
| where username in (jean_user)
| distinct src_ip;

let more_bad_ip =
InboundNetworkEvents
| where url == "https://devteam.galaxyneura.tech/search=top+secret+projects+come+on+you+gotta+gimme+something+interesting" or url == "https://devteam.galaxyneura.tech/onboarding"
| project src_ip;

let bad_doms =
PassiveDns
| where ip in (bad_ips) or ip in (more_bad_ip)
| distinct domain;

let all_bad_ips =
PassiveDns
| where domain in (bad_doms)
| distinct ip;

InboundNetworkEvents
| where src_ip in (all_bad_ips)
```

### Notes

- The frustrated search occurred on `2025-02-13`.
- Earlier browsing activity was observed on `2025-02-05`.

### Answer

`2025-02-05`

---

## Question 12

That was before Jean Song was hired! And by the look of it, they were looking at employment opportunities…

Which url did Jean probably use to apply at Galaxy Neura?

### KQL Query

```kql
let jean_user =
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project username;

let bad_ips =
AuthenticationEvents
| where username in (jean_user)
| distinct src_ip;

let more_bad_ip =
InboundNetworkEvents
| where url == "https://devteam.galaxyneura.tech/search=top+secret+projects+come+on+you+gotta+gimme+something+interesting" or url == "https://devteam.galaxyneura.tech/onboarding"
| project src_ip;

let bad_doms =
PassiveDns
| where ip in (bad_ips) or ip in (more_bad_ip)
| distinct domain;

let all_bad_ips =
PassiveDns
| where domain in (bad_doms)
| distinct ip;

InboundNetworkEvents
| where src_ip in (all_bad_ips)
| where url contains "career"
```

### Notes

- The results contain the Galaxy Neura careers page.
- Jean appears to have searched for freelance opportunities.

### Answer

`https://galaxyneura.tech/career/current-openings/freelance-opportunities-all-hands-on-deck`

---

## Question 13

Jean applied, apparently. And Jean was hired, obviously.

What email address did Jean use during the recruitment process?

### KQL Query

First, identify non-company recipients and the shared HR address:

```kql
let emp_emails =
Employees
| where email_addr contains "@galaxyneura.tech"
| distinct email_addr;

Email
| where recipient endswith "@galaxyneura.tech" and recipient !in (emp_emails)
| distinct recipient
```

Then search the recruitment correspondence:

```kql
let hr_email =
Employees
| where role contains "hr"
| project email_addr;

Email
| where sender in (hr_email) or sender in ("hr@galaxyneura.tech")
| where timestamp >= datetime(2025-02-05T12:29:55.000Z)
| where recipient contains "jean" or sender contains "jean"
```

### Answer

`jeansong4@proton.me`

---

## Question 14

When did Jean say they received their work laptop? (paste the full timestamp)

### KQL Query

```kql
Email
| where recipient == "hr@galaxyneura.tech"
| where sender contains "jean"
```

### Notes

- Review Jean's email confirming receipt of the company laptop.

### Answer

`2025-02-11T10:14:57Z`

---

## Question 15

Let's see what they did once they got their hands on the company-issued computer.

It looks like Jean downloaded and installed a remote access tool.

What command did they use to download it?

### KQL Query

```kql
let jean_host =
Employees
| where name has "Jean"
| distinct hostname;

ProcessEvents
| where hostname in (jean_host)
| where process_commandline contains "download"
```

### Notes

- The first relevant log contains a GitHub release URL being downloaded with `curl`.
- The downloaded executable is the remote access tool.

### Answer

`curl -L "https://github.com/rustdesk/rustdesk/releases/download/1.3.8/rustdesk-1.3.8-x86_64.exe" -o rustdesk.exe`

---

## Question 16

What is the name of the remote access tool?

### Notes

- The tool name is visible in the download command from Question 15.

### Answer

`rustdesk.exe`

---

## Question 17

It seems Jean had some trouble setting up another tool the next day.

According to their browsing history, what option did they want to add to that second tool?

### KQL Query

```kql
let jean_ip =
Employees
| where name has "Jean"
| distinct ip_addr;

OutboundNetworkEvents
| where src_ip in (jean_ip)
| where timestamp >= datetime(2025-02-12T08:00:23.000Z)
```

### Notes

- The timestamp marks the activity after Jean downloaded the remote access tool.
- Review the browsing activity on February 13.
- The search query references the requested option.

### Answer

`mouse jiggler`

---

## Question 18

🎁 Bonus question 🎁

(You will have to do research outside the data, by using other tools or finding some real life threat reports.)

Looking at the IP addresses linked to Jean, can you find which VPN they used?

### KQL Query

```kql
let jean_user =
Employees
| where email_addr == "jean_song@galaxyneura.tech"
| project username;

let bad_ips =
AuthenticationEvents
| where username in (jean_user)
| distinct src_ip;

let more_bad_ip =
InboundNetworkEvents
| where url == "https://devteam.galaxyneura.tech/search=top+secret+projects+come+on+you+gotta+gimme+something+interesting" or url == "https://devteam.galaxyneura.tech/onboarding"
| project src_ip;

let bad_doms =
PassiveDns
| where ip in (bad_ips) or ip in (more_bad_ip)
| distinct domain;

let all_bad_ips =
PassiveDns
| where domain in (bad_doms)
| distinct ip;

InboundNetworkEvents
| where src_ip in (all_bad_ips)
| distinct src_ip
```

### Notes

- This query identifies the IP addresses associated with Jean's activity.
- There are 4 linked IP addresses.
- Perform OSINT on the IP addresses.
- VirusTotal was checked for `199.115.99.34`.
- In the Google results shown for the IP, the VPN can be identified by searching for `VPN`.

**VirusTotal Reference**

```text
hxxps://www[.]virustotal[.]com/gui/ip-address/199.115.99.34/details
```

### Answer

`AstrillVPN`

---

## Question 19

THE IT WORKERS FROM ANOTHER COUNTRY!

That was what was gnawing at the back of your mind (back in Q5)!! It was all anyone could talk about a few weeks back! Of course!

[rember](hxxps://media4[.]giphy[.]com/media/v1.Y2lkPTc5MGI3NjExbnU2Z2NqMWQ4Mjd3YzBqaTl3Zjl6dXVndGo1ODZqaHF3OXp1bXg1OSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/Dl1HHr2oiivwnNt0Kv/giphy.gif)

Let's recap:

- Jean Song (or whatever they're really called 😒) applied to the company, nailed the interviews, and got hired.
- They got the company-issued laptop delivered to another location, most likely a laptop farm.
- They connected to that laptop via a VPN to mask their real location.
- They installed their own remote access tool and a KVM over IP on the laptop to be able to access it more easily.
- Since they had access to the company's code repositories, they look for sensitive stuff and proceeded to copy it to their own account, then deleted the original.
- Finally they asked for a ransom 🤑

Once you shared your findings, Jean was very much kicked out of the company. Thankfully, Galaxy Neura had a backup of the code they deleted, so all that teamwork wasn't lost. Unfortunately, the CEO refused to pay anything, and Jean still left with the copy they stole.

Type `You never lose. You either win or you learn.` to finish this investigation.

### Answer

`You never lose. You either win or you learn.`

---