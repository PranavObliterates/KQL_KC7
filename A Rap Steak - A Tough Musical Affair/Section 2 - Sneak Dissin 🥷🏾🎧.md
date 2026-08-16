# Section 2: Sneak Dissin 🥷🏾🎧

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

---

## Question 1

Since everyone is on high alert, you had your web administrator run a blind hunt for potential adversaries trying to claim the Dwake bounty.

After a few hours in the trenches, your web administrator found something. Someone was searching the Studio website for "unreleased diss tracks."

The web administrator saw it for a second, but in the chaos of the excitement, they accidentally cleared it before noting the IP that was doing this search.

What IP was used to search for `unreleased diss tracks` at Beats Studios?

### KQL Query

```kql
InboundNetworkEvents
| where url contains "unreleased"
| project src_ip
```

### Answer

`116.236.111.174`

---

## Question 2

How many total requests do we see from this IP?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "116.236.111.174"
| count
```

### Answer

`16`

---

## Question 3

The browsing activity from this IP is pretty incriminating. It appears they are interested in the very objective that Dwake had set for them.

The threat actor behind this IP was searching the location of what server?

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "116.236.111.174"
| where url contains "server"
```

### Notes

- Two logs are returned.
- The URLs show that the threat actor searched for the production server.

### Answer

`production`

---

## Question 4

Apparently, this fool thinks our website is a magic eight ball. They asked a pretty silly question.

Complete this: `Which one is better? _______________`

### KQL Query

```kql
InboundNetworkEvents
| where src_ip == "116.236.111.174"
| where url contains "which"
| extend extracted = url_decode(url_decode(url))
```

### Answer

`money, power or respect?`

---

## Question 5

This threat actor sounds interesting enough to follow. Let's enumerate their infrastructure to see if they did anything else.

We can use the IP address to search the `PassiveDns` table and find associated domains.

What was the most common domain that resolved to the threat actor's IP?

### KQL Query

```kql
PassiveDns
| where ip == "116.236.111.174"
| summarize count() by domain
```

### Answer

`lytpackhacks.com`

---

## Question 6

What was the other domain that resolved to that IP?

### Notes

- Use the results from the Passive DNS query in Question 5.

### Answer

`sneakdisstools.com`

---

## Question 7

Let's Pivot again!

What additional IP did these domains resolve to?

### KQL Query

```kql
let domains =
PassiveDns
| where ip == "116.236.111.174"
| distinct domain;

PassiveDns
| where domain in (domains)
| distinct ip
| where ip != "116.236.111.174"
```

### Answer

`229.50.59.91`

---

## Question 8

You make a post in the ME-ISAC portal about the sort of activity you've been observing.

ME-ISAC is the Information Sharing and Analysis Center for the Media and Entertainment industry, where companies in the media industry share information about the cyber threats they are seeing.

You also share the two IPs that you've been investigating. Soon after, several other company chime back that they've seen similar activity.

This activity surprisingly leads to the download of a `xmrig.exe` file. You take this fresh new intel to your `ProcessEvents` logs and get several hits.

How many processes do you see on your network that make reference to an `xmrig.exe` file?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "xmrig.exe"
| count
```

### Answer

`32`

---

## Question 9

Do some online research on `xmrig.exe.` Apparently, this is some open-source malware that bad guys use to make extra cash.

Hackers use `xmrig.exe` to mine for _____

### Notes

- Perform OSINT on `xmrig.exe`.
- The tool is used for cryptocurrency mining.

### Answer

`cryptocurrency`

---

## Question 10

Let's drill down on one of the hosts to see what else happened on it.

First, we'll select a host (computer) to drill down on.

Which host did we first see this command on?

### KQL Query

```kql
ProcessEvents
| where process_commandline contains "xmrig.exe"
| summarize firstseen = min(timestamp) by hostname
```

### Notes

- Review the earliest `firstseen` timestamp and identify the corresponding hostname.

### Answer

`YBI4-MACHINE`

---

## Question 11

When did we observe the `xmrig.exe` on that machine?

### Notes

- Use the results from the previous query and identify the earliest timestamp for `YBI4-MACHINE`.

### Answer

`2024-06-10T15:42:29Z`

---

## Question 12

Right after running `xmrig.exe`, the threat actors ran another command to establish persistence.

What command did the threat actors run to establish persistence?

### KQL Query

```kql
ProcessEvents
| where timestamp >= datetime(2024-06-10T15:42:29Z)
| where hostname == "YBI4-MACHINE"
```

### Notes

- Isolate the host where `xmrig.exe` was first observed.
- Review the process logs immediately after the miner executed.
- The second log contains a `schtasks` command.
- `schtasks` is used to create scheduled tasks, which can establish persistence.

### Answer

`C:\Windows\System32\schtasks.exe /Create /SC MINUTE /TN "Update service for Windows Service" /TR "PowerShell.exe -ExecutionPolicy bypass -windowstyle hidden -File C:\Users\Administrator\update.ps1" /MO 30 /F`

---

## Question 13

Seven days later, the threat actors returned to check on their rig, and decided to taunt you while they were at it!

What message did they leave to tell you what they had done?

### KQL Query

```kql
ProcessEvents
| where timestamp >= datetime(2024-06-17)
| where hostname == "YBI4-MACHINE"
```

### Notes

- Review the process activity on `YBI4-MACHINE` starting on June 17.
- An encrypted PowerShell command is observed.
- The command is Base64 encoded.
- CyberChef was used to decode the Base64 payload and then reverse the decoded text.

**CyberChef Reference**

```text
hxxps://gchq[.]github[.]io/CyberChef/
```

**Recipe**

```text
From Base64
→ Reverse
```

**CyberChef Recipe Link**

```text
hxxps://gchq[.]github[.]io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)Reverse('Character')&input=UXpwY1YybHVaRzkzYzF4VGVYTjBaVzB6TWx4d2IzZGxjbk5vWld4c0xtVjRaU0F0VG05d0lDMUZlR1ZqZFhScGIyNVFiMnhwWTNrZ1lubHdZWE56SUMxRGIyMXRZVzVrSUNJa2NtVjJJRDBnSnlJbmNuSnljbkp5Y25KeWNuSnljbkpsWldWbFpXVnVhVzF2ZEhCNWNtTWdZU0JrWld4c1lYUnpibWtnZEhOMWFpQkpKeUIwZFhCMGRVOHRaWFJwY2xjaUlHUnVZVzF0YjBNdElHVjRaUzVzYkdWb2MzSmxkMjl3Snpza2NtVjJXem82TFRGZEln
```

### Answer

`I just installed a cryptomineeeeeerrrrrrrrrrrrrr`

---

## Question 14

What second message did they leave to rub salt in the wound?

### KQL Query

```kql
ProcessEvents
| where timestamp >= datetime(2024-06-17)
| where hostname == "YBI4-MACHINE"
| where process_commandline contains "bypass"
```

### Notes

- Five logs contain `bypass` in the command line.
- Attempt to decode each relevant Base64 payload.
- One of the commands produces decimal values after Base64 decoding.
- Convert the decimal values to ASCII.
- The decoded text is then reversed in CyberChef.

**CyberChef Reference**

```text
hxxps://gchq[.]github[.]io/CyberChef/
```

**Decimal-to-ASCII Reference**

```text
hxxps://www[.]prepostseo[.]com/tool/decimal-to-ascii
```

**Base64 Recipe**

```text
From Base64
```

**CyberChef Recipe Link**

```text
hxxps://gchq[.]github[.]io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=VzFOMFVtbE9aMTA2T2twdlNXNG9JQ2NuTENCYlEyaGhVbHRkWFNnMk55d2dOVGdzSURreUxDQTROeXdnTVRBMUxDQXhNVEFzSURFd01Dd2dNVEV4TENBeE1Ua3NJREV4TlN3Z09USXNJRGd6TENBeE1qRXNJREV4TlN3Z01URTJMQ0F4TURFc0lERXdPU3dnTlRFc0lEVXdMQ0E1TWl3Z01URXlMQ0F4TVRFc0lERXhPU3dnTVRBeExDQXhNVFFzSURFeE5Td2dNVEUwTENBeE1ERXNJREV3T0N3Z01UQTRMQ0EwTml3Z01UQXhMQ0F4TWpBc0lERXdNU3dnTXpJc0lEUTFMQ0EzT0N3Z01URXhMQ0F4TVRJc0lETXlMQ0EwTlN3Z05qa3NJREV5TUN3Z01UQXhMQ0E1T1N3Z01URTNMQ0F4TVRZc0lERXdOU3dnTVRFeExDQXhNVEFzSURnd0xDQXhNVEVzSURFd09Dd2dNVEExTENBNU9Td2dNVEl4TENBek1pd2dPVGdzSURFeU1Td2dNVEV5TENBNU55d2dNVEUxTENBeE1UVXNJRE15TENBME5Td2dOamNzSURFeE1Td2dNVEE1TENBeE1Ea3NJRGszTENBeE1UQXNJREV3TUN3Z016SXNJRE0wTENBek5pd2dNVEUwTENBeE1ERXNJREV4T0N3Z016SXNJRFl4TENBek1pd2dNemtzSURNMExDQXpPU3dnTVRFMUxDQXhNVGNzSURNeUxDQXhNREVzSURFd055d2dNVEExTENBeE1EZ3NJRE15TENBeE1UWXNJREV4TVN3Z01URXdMQ0F6TWl3Z01USXhMQ0F4TURFc0lERXdOQ3dnTVRFMkxDQXpNaXdnTkRRc0lERXhOU3dnTVRFM0xDQXpNaXdnTVRBeExDQXhNRGNzSURFd05Td2dNVEE0TENBek1pd2dNVEUyTENBeE1URXNJREV4TUN3Z016SXNJREV5TVN3Z01UQXhMQ0F4TURRc0lEZzBMQ0F6T1N3Z016SXNJREV4Tml3Z01URTNMQ0F4TVRJc0lERXhOaXdnTVRFM0xDQTNPU3dnTkRVc0lERXdNU3dnTVRFMkxDQXhNRFVzSURFeE5Dd2dPRGNzSURNMExDQXpNaXdnTVRBd0xDQXhNVEFzSURrM0xDQXhNRGtzSURFd09Td2dNVEV4TENBMk55d2dORFVzSURNeUxDQXhNREVzSURFeU1Dd2dNVEF4TENBME5pd2dNVEE0TENBeE1EZ3NJREV3TVN3Z01UQTBMQ0F4TVRVc0lERXhOQ3dnTVRBeExDQXhNVGtzSURFeE1Td2dNVEV5TENBek9Td2dOVGtzSURNMkxDQXhNVFFzSURFd01Td2dNVEU0TENBNU1Td2dOVGdzSURVNExDQTBOU3dnTkRrc0lEa3pMQ0F6TkNrcGZDWWdLQ2huZGlBbktrMUVjaW9uS1M1T1lXMUZXek1zTVRFc01sMHRhbTlwVGc
```

**Decimal Input Used**

```text
67, 58, 92, 87, 105, 110, 100, 111, 119, 115, 92, 83, 121, 115, 116, 101, 109, 51, 50, 92, 112, 111, 119, 101, 114, 115, 104, 101, 108, 108, 46, 101, 120, 101, 32, 45, 78, 111, 112, 32, 45, 69, 120, 101, 99, 117, 116, 105, 111, 110, 80, 111, 108, 105, 99, 121, 32, 98, 121, 112, 97, 115, 115, 32, 45, 67, 111, 109, 109, 97, 110, 100, 32, 34, 36, 114, 101, 118, 32, 61, 32, 39, 34, 39, 115, 117, 32, 101, 107, 105, 108, 32, 116, 111, 110, 32, 121, 101, 104, 116, 32, 44, 115, 117, 32, 101, 107, 105, 108, 32, 116, 111, 110, 32, 121, 101, 104, 84, 39, 32, 116, 117, 112, 116, 117, 79, 45, 101, 116, 105, 114, 87, 34, 32, 100, 110, 97, 109, 109, 111, 67, 45, 32, 101, 120, 101, 46, 108, 108, 101, 104, 115, 114, 101, 119, 111, 112, 39, 59, 36, 114, 101, 118, 91, 58, 58, 45, 49, 93, 34
```

**Decoded ASCII**

```text
C:\Windows\System32\powershell.exe -Nop -ExecutionPolicy bypass -Command "$rev = '"'su ekil ton yeht ,su ekil ton yehT' tuptuO-etirW" dnammoC- exe.llehsrewop';$rev[::-1]"
```

**Reversed Output**

```text
"]1-::[ver$;'powershell.exe -Command "Write-Output 'They not like us, they not like us'"' = ver$" dnammoC- ssapyb yciloPnoitucexE- poN- exe.llehsrewop\23metsyS\swodniW\:C
```

**CyberChef Reverse Link**

```text
hxxps://gchq[.]github[.]io/CyberChef/#recipe=Reverse('Character')&input=QzpcV2luZG93c1xTeXN0ZW0zMlxwb3dlcnNoZWxsLmV4ZSAtTm9wIC1FeGVjdXRpb25Qb2xpY3kgYnlwYXNzIC1Db21tYW5kICIkcmV2ID0gJyInc3UgZWtpbCB0b24geWVodCAsc3UgZWtpbCB0b24geWVoVCcgdHVwdHVPLWV0aXJXIiBkbmFtbW9DLSBleGUubGxlaHNyZXdvcCc7JHJldls6Oi0xXSI&oeol=NEL
```

### Answer

`They not like us, they not like us`

---

## Question 15

We still have no idea how the threat actor got in.

You noticed some weird behavior around the login activity to the compromised hosts.

How many `user_agents` were used to log in to more than one of the compromised hosts?

### KQL Query

```kql
let compro_hosts =
ProcessEvents
| where process_commandline contains "xmrig.exe"
| distinct hostname;

AuthenticationEvents
| where hostname in (compro_hosts)
| summarize dcount(hostname) by user_agent
| where dcount_hostname > 1
| count
```

### Answer

`13`

---

## Question 16

How many of those `user_agents` were used to log in to all of the compromised hosts?

### KQL Query

```kql
let compro_hosts =
ProcessEvents
| where process_commandline contains "xmrig.exe"
| distinct hostname;

AuthenticationEvents
| where hostname in (compro_hosts)
| summarize dcount(hostname) by user_agent
| where dcount_hostname == 32
| count
```

### Answer

`9`

---

## Question 17

How many failures did we see from user agent `"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_9_1; en-US) Gecko/20100101 Firefox/70.0"`?

### KQL Query

```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_9_1; en-US) Gecko/20100101 Firefox/70.0"
| where result contains "fail"
| count
```

### Answer

`592`

---

## Question 18

What was the most prevalent IP used by the threat actor when this user agent was present?

### KQL Query

```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_9_1; en-US) Gecko/20100101 Firefox/70.0"
| summarize count(user_agent) by src_ip
| sort by count_user_agent desc
```

### Answer

`116.236.111.174`

---

## Question 19

What kind of attack did the threat actor use as an initial access vector?

### KQL Query

```kql
AuthenticationEvents
| where user_agent == "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_9_1; en-US) Gecko/20100101 Firefox/70.0"
| summarize count(hostname) by password_hash
```

### Notes

- Multiple hostnames share the same password hashes.
- This pattern indicates a password spray attack.

### Answer

`Password spray`

---

## Question 20

What is the MITRE ATT&CK technique ID for this attack type?

### Notes

- Search the MITRE ATT&CK technique for password spraying.

### Answer

`T1110.003`

---