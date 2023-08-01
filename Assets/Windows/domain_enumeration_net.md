# net.exe // Domain enumeration using net.exe

### What is net.exe:
The genuine net.exe file is a software component of Microsoft Windows Operating System by Microsoft Corporation.
Microsoft's "net.exe" process should reside in "C:\Windows\System32" and should not be removed. It is a utility for use in an elevated command prompt, or in script and batch files to simplify and standardize network administrator tasks. Its multiple subcommands allow starting, pausing, or stopping Windows services, adjusting network account requirements such as password characteristics, mapping shared disk resources to drive letters, and other functions, on local or remote client or server computers. This includes stopping or starting the IPv6 protocol. Its "send" subcommand for messages has been disabled since Windows Vista, (use "msg.exe" instead). Some legacy software products still call "net1.exe" which once was an alternative version with fixes to "Y2K" problems; that name has been kept but now functions identically.

### Severity:
Medium

### MITER ATT&CK:
- TA0007 > T1087 > [Valid Accounts: Domain Accounts](https://attack.mitre.org/techniques/T1078/002/)

### Resources:
- https://www.google.com/search?client=firefox-b-1-e&q=what+is+net.exe
- https://learn.microsoft.com/en-us/windows/win32/winsock/net-exe-2
- https://tryhackme.com/room/adenumeration

### KQL Query:
```
event.action:"start" and process.name:"net.exe" and process.args:(("/domain" and "group") or ("/domain" and "user") or ("/domain" and "accounts"))
```

### Notes:
- This alert was used to detect the following commands:
    - net localgroup administrators /domain
    - net group “Domain Controllers” /domain
    - net group “Domain Admins” /domain
    - net user /domain <username>
    - net user /domain
    - net group /domain
    - net accounts /domain
- This rule watches for the call of net.exe with the process argument /domain in combination with group, user, or accounts.
