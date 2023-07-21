# example.exe // Rule Name

### What is example.exe:
example.exe is a made up exacutable that I made to demo this template

### Attacks:
- Download
- Alternate data streams

### Severity:
Medium

### MITER ATT&CK:
- TA0001 > T1078 > T1078.001 > [Valid Accounts: Default Accounts](https://attack.mitre.org/techniques/T1078/001/)

### Resources:
- hxxps://example.exe/fake
- hxxps://example.exe/fake/attack

### KQL Query:
```
action:"start" and process.name:"example.exe" and process.args:("-hack" and "-the" and "-plannet")
```

### Notes:
Does not in fact hack the plannet...




