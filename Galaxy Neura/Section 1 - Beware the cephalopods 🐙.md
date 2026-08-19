# Section 1: Beware the cephalopods 🐙

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

---

## Question 1

Welcome to Galaxy Neura!

A thriving and growing company specialised in Brain Computer Interface (BCI) 🧠🖥 While you've been spending your whole teenager years dreaming about a cyberpunk future, *they* have been busy making sure humanity would get there before you die!

And now your little nerd heart is over the moon because you get to work for them 🤩 every! day! You couldn't be happier! Your mission is to protect and defend them against bad guys trying to get into their network. And there's bound to be some, maybe from jealous companies that did not manage to get as far and popular as Galaxy Neura did… 😒 It's like in the movies, you know!

So let's hunt for those bad guys, shall we?

Type `Trust no one, question everything!` to start your investigation.

### Answer

`Trust no one, question everything!`

---

## Question 2

Threat hunting isn’t about waiting for alerts to tell you something is wrong. It’s about proactively searching for signs of compromise before they trigger alarms.

Last night, you read an article about malware being delivered through a perfectly legitimate file-sharing service to evade detection at the inbox level. A lot of important research is done at Galaxy Neura, and research implies collaboration between people. So you figured it could be an attack vector used against your colleagues. Security tools won't always catch these types of attacks, and you can't just permablock those legitimate services. So it's up to you to keep an eye out for potential trouble.

The file-sharing services mentioned in the article were: DocuSign, Microsoft SharePoint, and Dropbox. Time to gather intelligence and find out if any of these services sent emails to your organization.

How many emails did your colleagues receive?

### KQL Query

```kql
Email
| where recipient endswith "galaxyneura.tech"
| where sender has_any ("@sharepointonline.com", "@docusign.net", "@dropbox.com")
```

### Answer

`1`

---

## Question 3

Not many hits! It should be quick to investigate. There is no need to worry yet, it could well be a perfectly legitimate email. You need both more context and more details before you sound the alarm bell.

What is the job role of the recipient of the Dropbox email?

### KQL Query

```kql
Email
| where recipient endswith "galaxyneura.tech"
| where sender has_any ("@sharepointonline.com", "@docusign.net", "@dropbox.com")
| join kind=inner Employees on $left.recipient == $right.email_addr
| project role
```

### Answer

`Senior Neuroscientist`

---

## Question 4

So Rick Kingsley is a scientist. He's definitely the type of person who would receive research papers.

Now, you need to figure out if Rick expected that email or if he knew the person sharing that paper.

What is the name of the person who shared the file?

### KQL Query

```kql
Email
| where recipient endswith "galaxyneura.tech"
| where sender has_any ("@sharepointonline.com", "@docusign.net", "@dropbox.com")
```

### Notes

- Review the subject of the email to identify the sender's name.

### Answer

`Olivia Octopus`

---

## Question 5

Thankfully, you have a full name. We can see if Rick had any prior contact with Olivia.

How many emails did the two of them exchange?

### KQL Query

```kql
Email
| where sender has_any ("octopus", "kingsley")
| where recipient has_any ("octopus", "kingsley")
```

### Answer

`8`

---

## Question 6

Rick and Olivia had a discussion spanning a few days, and Rick was indeed expecting a file from Olivia.

But wait, do they really know each other? Take a look at the very first email that Olivia sent. It mentions a popular networking platform.

When did Rick first connect with Olivia? (paste the full timestamp)

### KQL Query

```kql
Email
| where recipient == "rick_kingsley@galaxyneura.tech"
| where subject contains "octopus"
```

### Answer

`2025-03-05T14:37:02Z`

---

## Question 7

It is very, very recent. They might have never met irl. While it is absolutely plausible in today's hyper connected world, in the context of your hunt, it pushes the whole thing towards suspicious territory.

Let us go back to the emails they exchanged to gather other clues. There is some mention of a renowned university.

What is the domain used by Olivia in her email address?

### KQL Query

```kql
Email
| where sender has_any ("octopus", "olivia")
```

### Notes

- Review the sender address.
- The domain after `@` is `harvards.edu`.

### Answer

`harvards.edu`

---

## Question 8

Whelp. That is *not* the official domain used by Harvard University… But it would fool anyone not paying close attention. Especially a scientist excited at the prospect of nerding out about their favourite subject with a star-eyed student 😬

Rick sent documents to Olivia before she returned the favour with his permission.

What is the name of the last paper he shared with her? (extension included)

### KQL Query

```kql
Email
| where sender has_any ("octopus", "kingsley")
| where recipient has_any ("octopus", "kingsley")
| sort by timestamp asc
```

### Notes

- Review the `attachments` column.
- Three PDF files are visible.
- Identify the most recent attachment.

### Answer

`Secret_unethical_research_putting_the_apes_on_mute.pdf`

---

## Question 9

Oh, Rick, Rick, Rick…

What happened there is Rick shared files he shouldn't have. Everyone at Galaxy Neura is under NDA. He's going to be in trouble once you finish your investigation and deliver your report. Because even if you don't find anything more (and that is a big if), Rick would now be considered an insider threat, leaking out proprietary data of his own volition. Let's hope for him that it doesn't get worse.

Rick downloaded the file Olivia shared. What is the sha256 of that pdf?

### KQL Query

```kql
let rick_host =
Employees
| where name has "Rick Kingsley"
| project hostname;

FileCreationEvents
| where timestamp >= datetime(2025-03-07T16:13:04.000Z)
| where hostname in (rick_host)
| where filename endswith ".pdf"
| project sha256
```

### Notes

- There is only one PDF file on Rick's host after the time they emailed about a file being shared.
- Retrieve the `sha256` value for that file.

### Answer

`8ced3a034e25ae9669aae44af738ce16510122a0c0e23a4f5fcc32720f493fe8`

---

## Question 10

The pdf file looks legitimate. But that was not the full name of the file in the Dropbox email now, was it?

What was the extra extension in the email?

### KQL Query

```kql
let rick_host =
Employees
| where name has "Rick Kingsley"
| project hostname;

FileCreationEvents
| where timestamp >= datetime(2025-03-07T16:13:04.000Z)
| where hostname in (rick_host)
| where filename contains ".pdf"
```

### Notes

- Review the full filename and identify the additional extension.

### Answer

`.svg`

---

## Question 11

A file with a double extension, like we found here, is usually very, very suspicious.

Let's see if anything else was downloaded around that time.

How many files, including the pdf, appeared on Rick's machine around that time?

### KQL Query

```kql
let rick_host =
Employees
| where name has "Rick Kingsley"
| project hostname;

FileCreationEvents
| where hostname in (rick_host)
| where timestamp >= datetime(2025-03-08) and timestamp < datetime(2025-03-09)
| order by timestamp asc
```

### Answer

`4`

---

## Question 12

Now you can sound the alarm.

Looks like the Dropbox link actually downloaded a `.zip` archive, that was then opened to spawn extra files, including the pdf. In that instance, the pdf file acted as a decoy, so that Rick would not suspect anything.

What is the full command that was used to open the archive?

### KQL Query

```kql
let rick_host =
Employees
| where name has "Rick Kingsley"
| project hostname;

ProcessEvents
| where hostname in (rick_host)
| where timestamp >= datetime(2025-03-08) and timestamp < datetime(2025-03-09)
| order by timestamp asc
```

### Answer

`Expand-Archive -Path C:\Users\rikingsley\Downloads\olivia_bci_research.zip -Force -DestinationPath C:\Users\rikingsley\AppData\Roaming`

---

## Question 13

Going back to the files contained in the zip archive, what automation tool was used as a loader?

### KQL Query

```kql
let rick_host =
Employees
| where name has "Rick Kingsley"
| project hostname;

FileCreationEvents
| where hostname in (rick_host)
| where timestamp >= datetime(2025-03-08T08:51:02.000Z)
```

### Notes

- The file activity shows `autoit_loader.com`.
- This identifies **AutoIt** as the loader.

### Answer

`autoit`

---

## Question 14

The tool you found in Q13 was used to download extra malware.

What is the name of the executable for that malware?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
| where process_name contains "autoit"
```

### Notes

- Review the `process_commandline` field.
- The executable referenced by the AutoIt process is the malware.

### Answer

`nymeria.exe`

---

## Question 15

Which domain was it downloaded from?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
| where process_name contains "autoit"
| extend dom = tostring(parse_url(process_commandline).Host)
| project dom
```

### Answer

`bigbrainssmallbrains.net`

---

## Question 16

Before you dive into what happened once the malware was downloaded, let's take a closer look at that domain, as it will tell us more about the threat actor's infrastructure.

How many IP addresses did it resolve to?

### KQL Query

```kql
PassiveDns
| where domain == "bigbrainssmallbrains.net"
| distinct ip
| count
```

### Answer

`4`

---

## Question 17

Let's add the domain from Olivia's email address to the list. You now have 10 IP addresses linked to the threat actor.

You can use those IP addresses to see if the threat actor browsed to the company's network before the attack, and if they did, what they were looking for. Leveraging publicly available information is common during the reconnaissance phase of an attack. Looking into it can give great insights into their methods, for example how they chose their victims or what they want to ultimately achieve.

How many times did the threat actor browse to Galaxy Neura's network?

### KQL Query

```kql
let bad_ips =
PassiveDns
| where domain in ("bigbrainssmallbrains.net", "harvards.edu")
| distinct ip;

InboundNetworkEvents
| where src_ip in (bad_ips)
```

### Answer

`12`

---

## Question 18

It looks like they really focused on Rick Kingsley after they ran a search for a specific kind of researcher.

What type of researcher were they looking for? (only enter the search terms, replace the + by spaces)

### KQL Query

First, identify the reconnaissance events containing `researcher`:

```kql
let bad_ips =
PassiveDns
| where domain in ("bigbrainssmallbrains.net", "harvards.edu")
| distinct ip;

InboundNetworkEvents
| where src_ip in (bad_ips)
| where url contains "researcher"
```

Then isolate the specific search query:

```kql
let bad_ips =
PassiveDns
| where domain in ("bigbrainssmallbrains.net", "harvards.edu")
| distinct ip;

InboundNetworkEvents
| where src_ip in (bad_ips)
| where url contains "gullible"
| extend query = replace_string(url, "+", " ")
```

### Notes

- Three relevant logs are returned.
- The third log contains the specific query referenced by the question.
- Replace `+` with spaces.

### Answer

`most gullible researcher at Galaxy Neura`

---

## Question 19

Well, it seems they hit the jackpot, didn't they?

Alright. Back to the malware then. Once they downloaded Nymeria, the threat actor made sure they would not lose access to Rick's machine. This is called persistence.

What legitimate Windows tool did they use to do this?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
| where process_commandline contains "nymeria"
```

### Notes

- Review the process name associated with the persistence activity.

### Answer

`regedit.exe`

---

## Question 20

This all happened a few days ago. It might still be an ongoing situation 😱 Better escalate so more eyes can get on this and help stop the threat if they're still around inside the network.

In the meantime, you should keep looking into what happened next on Rick's machine. Once a threat actor gains access, they usually do some discovery on the machine and/or network.

How many discovery commands did "Olivia" run?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
```

### Notes

- Search for common discovery commands.
- The following six commands were identified:
  - `whoami`
  - `systeminfo`
  - `tasklist`
  - `netstat -an`
  - `ipconfig /all`
  - `wmic product get name`

### Answer

`6`

---

## Question 21

While looking further down the timeline, you notice a few encoded Powershell commands. Threat actor often encode malicious commands so that they will be harder to detect by automated tools.

Using a tool like CyberChef, let's decode the commands you can find to discover what the threat actor is doing.

What is "Olivia" trying to steal in the first Powershell command?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
```

### Notes

- After the final discovery command, `wmic product get name`, an encoded PowerShell command appears.
- Decode the Base64 payload using CyberChef.

**CyberChef Reference**

```text
hxxps://gchq[.]github[.]io/CyberChef/
```

**Recipe**

```text
From Base64
```

- The decoded command contains a variable named `creds`.

### Answer

`creds`

---

## Question 22

The script contained in the second Powershell command gives a huge clue about what Nymeria is capable of.

What type of malware usually behaves like that?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
| where process_commandline contains "-enc"
```

### Notes

- Review the second encoded PowerShell command.
- Decode the Base64 payload using CyberChef.

**CyberChef Reference**

```text
hxxps://gchq[.]github[.]io/CyberChef/
```

**Recipe**

```text
From Base64
```

- The decoded script captures keystrokes.
- This behaviour is characteristic of a keylogger.

### Answer

`keylogger`

---

## Question 23

The third command also steals the content of the clipboard!

In which folder of the threat actor's server is the data dumped?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
| where process_commandline contains "-enc"
```

### Notes

- Review the third encoded PowerShell command.
- Decode the Base64 payload using CyberChef.

**CyberChef Reference**

```text
hxxps://gchq[.]github[.]io/CyberChef/
```

**Recipe**

```text
From Base64
```

- The decoded command identifies the destination folder used to dump the stolen data.

### Answer

`brain_dump`

---

## Question 24

The team in charge of shutting down the threat relays some good news to you. You detected everything early enough that only Rick was compromised. The threat actor did not have time to move on to other machines. That is a huge relief.

What file did "Olivia" manage to steal from Rick before they were shut down?

### KQL Query

```kql
ProcessEvents
| where hostname == "GWCY-MACHINE"
| where process_commandline contains "-enc"
```

### Notes

- Review the final encoded PowerShell command.
- Decode the Base64 payload using CyberChef.
- The decoded command references the stolen PDF file.

### Answer

`latest_super_secret_research_final_FINAL.pdf`

---

## Question 25

Congratulations! Your quick thinking saved the day!

To summarise, here's what happened:

- "Olivia", probably someone working for another company, wanted to steal proprietary information from Galaxy Neura.
- They started by doing some reconnaissance to find the perfect victim as an entry point.
- They established rapport with Rick and gained his trust quickly.
- Rick became an insider threat, as he willingly shared research he wasn't supposed to.
- "Olivia" escalated by compromising Rick's machine via a legitimate Dropbox email.
- The `.svg` file downloaded a zip archive that contained a decoy file, the PDF, and a malicious AutoIt executable.
- The legitimate AutoIt3 process ran the malicious script and downloaded Nymeria, a malware that acts as a keylogger and a RAT.
- They persisted Nymeria to maintain access via the Windows tool `regedit` and were able to exfiltrate data from Rick's machine over a period of days.

Type `Suspicion is the beginning of wisdom, and of madness.` to finish your day.

### Answer

`Suspicion is the beginning of wisdom, and of madness.`

---