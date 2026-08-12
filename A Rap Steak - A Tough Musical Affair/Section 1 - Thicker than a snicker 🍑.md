# Section 1: Thicker than a snicker 🍑

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

---

## Question 1

Welcome to the "Big Bass Legends" Beats Studio. This place, while flying under the radar, has been the secret powerhouse behind some of the best beats in the RAP game for years. The beats crafted here are the backbone of your favorite hip-hop tracks. To keep their golden touch from being tarnished by prying eyes, BBL Studios has always been shrouded in secrecy.

But things took a turn when BBL Studios decided to bring in the heavy hitter, MetroBus Boomin. This high-profile producer was expected to elevate their game to new heights. The studio knew this move would draw eyes, but they bet it would also bring them prestige and a hefty boost in revenue.

What they didn’t foresee was MetroBus Boomin getting tangled in the most notorious rap beef of our era. The studio found itself in the eye of the storm.

To make matters worse, rumors are swirling that MetroBus Boomin is cooking up a special beat aimed squarely at Dwake. This could be a daring play or a dangerous gamble that might just put BBL Studios in the crosshairs of some very unsavory characters.

Enter `here we go again` to continue.

### Answer

`here we go again`

---

## Question 2

Dwake the rapper was stuck in a corner and ready to lash out. Having been the victim of many a diss track by Cendrick the lyricist, Dwake felt betrayed, disrespected, and felt that he needed to do something, anything to redeem his honor.

Unfortunately, Dwake's ghost writers were on PTO. They were completely worn out from working ridiculous hours during the back and forth spat.

Yet, Dwake could not sit around and let MetroBus get any more licks at him. So the lover-boy rapper decided to resort to alternative means.

Dwake's twitter fingers turned to dark web fingers as he sought help from the dark depths of the internet. Allegedly, one of Dwake's people made a post on a hacking forum, promising a lofty prize of $5 million dollars, to anyone who could leak her a copy of Metro's upcoming beats- or stop the beats from being published at all.

As a Security Operations Center Analyst for BBL Studios, it's your job to protect the firm from these would-be hackers.

Enter `they don't want the smoke` to continue.

### Answer

`they don't want the smoke`

---

## Question 3

What is the name of the CEO at BBL Studios?

### KQL Query

```kql
Employees
| where role == "CEO"
```

### Answer

`Michaela Barnett`

---

## Question 4

What is the name of the Chief Music Producer?

### KQL Query

```kql
Employees
| where role == "Chief Music Producer"
```

### Answer

`MetroBus Boomin`

---

## Question 5

What is Darla's email address?

### KQL Query

```kql
Employees
| where name has "Darla Smith"
| project email_addr
```

### Answer

`darla_smith@bblbeatsstudio.com`

---

## Question 6

Now that we have Darla's email address, we can use it to locate the emails sent to her. The `Email` table contains records of all emails sent and received by employees at the company.

According to Darla, the suspicious email she received came from `admin@cosmeticsurgerybrazil.com`

What was the subject of the email sent to Darla?

### KQL Query

```kql
Email
| where recipient == "darla_smith@bblbeatsstudio.com"
| where sender == "admin@cosmeticsurgerybrazil.com"
| project subject
```

### Answer

`[EXTERNAL] FW: 💪 Why Do Pushups When You Can Look Like This with a BBL? 💪`

---

## Question 7

Darla provided us a copy of the email she received. Let's examine it.

Go back and look at the data.

What was the link inside the email?

### KQL Query

```kql
Email
| where recipient == "darla_smith@bblbeatsstudio.com"
| where sender == "admin@cosmeticsurgerybrazil.com"
| project link
```

### Answer

`https://getnewbodybrazil.com/files/online/images/sign_in`

---

## Question 8

What domain name was observed inside of that link?

### KQL Query

```kql
Email
| where recipient == "darla_smith@bblbeatsstudio.com"
| where sender == "admin@cosmeticsurgerybrazil.com"
| project link
| extend domain = tostring(parse_url(link).Host)
```

### Answer

`getnewbodybrazil.com`

---

## Question 9

What is Darla's IP address?

### KQL Query

```kql
Employees
| where name has "Darla Smith"
| project ip_addr
```

### Answer

`10.10.0.28`

---

## Question 10

Did Darla click on the malicious link in email? If so, copy and paste the timestamp of when she first clicked on the link.

### KQL Query

```kql
let darla_ip =
Employees
| where name has "Darla Smith"
| project ip_addr;

OutboundNetworkEvents
| where src_ip in (darla_ip)
| where url contains "getnewbodybrazil.com"
```

### Notes

- There are two logs for the URL.
- Use the earliest timestamp.

### Answer

`2024-07-15T10:47:09Z`

---

## Question 11

In the `url` column, we can also see if Darla entered her credentials in the phishing page.

It seems she ignored our security awareness training in this case. 😞

What url tells us that Darla entered her credentials on the phishing page? (Copy and paste the url.)

### Notes

- Review the two URL events from Question 10.
- The phishing URL contains Darla's username and password parameters.

### Answer

`https://getnewbodybrazil.com/files/online/images/sign_in?username=dasmith&password=**********`

---

## Question 12

Which one of the IPs logging to Darla's account is not like the others?

### KQL Query

```kql
AuthenticationEvents
| where username == "dasmith"
| summarize count() by user_agent
```

### Notes

- One user agent appears only once.
- Review the source IPs associated with the account.

### KQL Query

```kql
AuthenticationEvents
| where username == "dasmith"
| summarize count() by src_ip
```

### Notes

- One source IP also appears only once.
- Pivot to that IP:

### KQL Query

```kql
AuthenticationEvents
| where username == "dasmith"
| where src_ip == "253.104.180.97"
```

### Answer

`253.104.180.97`

---

## Question 13

When do we see that IP logging into Darla's account? (Enter the full timestamp.)

### KQL Query

```kql
AuthenticationEvents
| where username == "dasmith"
| where src_ip == "253.104.180.97"
| project timestamp
```

### Answer

`2024-07-15T11:47:09Z`

---

## Question 14

Did Darla have 2-factor authentication enabled? (yes/no)

### KQL Query

```kql
Employees
| where name has "Darla Smith"
| project mfa_enabled
```

### Answer

`no`

---

## Question 15

What six letter command was executed on Darla machine after the suspicious login?

### KQL Query

```kql
let darla_host =
Employees
| where name has "Darla Smith"
| project hostname;

ProcessEvents
| where hostname in (darla_host)
| where timestamp >= datetime(2024-07-15T11:47:09.000Z)
```

### Notes

- Review the `process_commandline` field manually after the suspicious login.

### Answer

`whoami`

---

## Question 16

How many of these discovery commands do we see on Darla's machine?

### Notes

- After `whoami`, the following discovery commands are observed:
  - `ipconfig /all`
  - `netstat -an`
  - `arp -a`
  - `tasklist /svc`
  - `systeminfo`
- Including `whoami`, there are 6 discovery commands in total.

### Answer

`6`

---

## Question 17

At this point, the threat actor realizes they have access to Darla's machine. But…they need to manually run additional commands on her machine to determine what they can steal.

The operator is busy (probably hacking somebody else) so they don't return for a few days.

On August 1st, the threat actor returned and decided that it was time to get the good stuff. They ran a command to find information about the Studio's 'marketing strategy' and saved it to a `.txt` file.

What is the name of the file that they save this information to?

### KQL Query

```kql
let darla_host =
Employees
| where name has "Darla Smith"
| project hostname;

ProcessEvents
| where hostname in (darla_host)
| where timestamp >= datetime(2024-08-01)
| extend file_txt = extract(@"([^\\]+.txt)", 1, process_commandline)
| distinct file_txt
```

### Answer

`marketing_files_list.txt`

---

## Question 18

As if that weren't enough, the threat actor decided to get Darla for more.

A few days later, the threat actor returned like the grinch for the rest of it. They targeted an entire folder on Darla's computer.

What common folder did the threat actor target to steal documents?

### KQL Query

```kql
let darla_host =
Employees
| where name has "Darla Smith"
| project hostname;

ProcessEvents
| where hostname in (darla_host)
| where timestamp > datetime(2024-08-01)
```

### Notes

- Review the process activity for common folder paths.
- `Documents` is repeatedly referenced.
- The `Exfil` folder was also investigated, followed by its parent directory.

### Answer

`Documents`

---

## Question 19

What is the name of the tool the threat actor used to prepare the data for exfiltration?

### Notes

- Review the same process activity from Question 18.
- A later command references a tool used to compress and prepare files for exfiltration.

### Answer

`7z`

---

## Question 20

The threat actor is crafty and decided to exfiltrate these files via FTP.

They stored their commands for this in a file.

What is the name of the file in which they stored their commands?

### KQL Query

```kql
let darla_host =
Employees
| where name has "Darla Smith"
| project hostname;

ProcessEvents
| where hostname in (darla_host)
| where timestamp > datetime(2024-08-01)
| where process_commandline contains "ftp"
```

### Notes

- Review the `process_commandline` field.
- Identify the `.txt` file containing the FTP commands.

### Answer

`ftp_commands.txt`

---

## Question 21

What IP did Darla send the most amount of data to?

### KQL Query

```kql
let darla_ip =
Employees
| where name has "Darla Smith"
| project ip_addr;

NetworkFlow
| where src_ip in (darla_ip)
| summarize sum(bytes) by dest_ip
| sort by sum_bytes desc
```

### Answer

`182.136.239.46`

---

## Question 22

What command did the threat actors use to delete all the stolen files?

### KQL Query

```kql
let darla_host =
Employees
| where name has "Darla Smith"
| project hostname;

ProcessEvents
| where hostname in (darla_host)
| where timestamp > datetime(2024-08-01)
| where process_commandline contains "Documents"
```

### Notes

- Review the commands where `Documents` is referenced.
- One of the commands uses `del` to remove the stolen files.
- Copy the entire command.

### Answer

`del C:\Users\dasmith\Documents\Exfil\*`

---

## Question 23

Ok, the threat actor stole some files, which is unfortunate. But these aren't the sensitive files that Dwake was paying for, so we are (sort of) in the clear.

Let's not get too comfortable. Surely there are more hackers to come!

Enter `we got this` to complete this section.

### Answer

`we got this`

---