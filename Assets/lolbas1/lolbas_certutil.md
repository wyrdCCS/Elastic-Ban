# certutil.exe // lolbas-certutil

### What is certutil.exe:
Certutil.exe is a command-line program, installed as part of Certificate Services. You can use certutil.exe to display certification authority (CA) configuration information, configures Certificate Services, backup and restore CA components. The program also verifies certificates, key pairs, and certificate chains.

### Attacks:
- [Download](https://lolbas-project.github.io/lolbas/Binaries/Certutil/#download)
- [Alternate data streams](https://lolbas-project.github.io/lolbas/Binaries/Certutil/#ads)
- [Encode](https://lolbas-project.github.io/lolbas/Binaries/Certutil/#encode)
- [Decode](https://lolbas-project.github.io/lolbas/Binaries/Certutil/#decode)

### Severity:
Medium

### MITER ATT&CK:
- T1105 > [Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- TA0005 > T1564 > T1564.004 > [Hide Artifacts: NTFS File Attributes](https://attack.mitre.org/techniques/T1564/004/)
- TA0005 > T1027 > [Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- TA0005 > T1140 > [Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)

### Resources:
- https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
- https://lolbas-project.github.io/lolbas/Binaries/Certutil/

### KQL Query:
```
event.type:"start" AND process.name:"certutil.exe" AND process.args:("-urlcache" OR "-verifyctl" OR "-encode" OR "-decode" OR "-decodehex")
```

### Notes:
This rule covers all methods listed for certutil.exe in the [lolbin project](https://lolbas-project.github.io)