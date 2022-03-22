# LetsEncryptRemediation

# How to run
- Run Powershell as Administrator and run command:
```powershell
$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/LetsEncryptRemediation/main/runbook.ps1;Invoke-Expression $($s.Content)
```
## In some cases you might run into...
**The request was aborted: Could not create SSL/TLS Secure Channel.**
- Use This command:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/LetsEncryptRemediation/main/runbook.ps1;Invoke-Expression $($s.Content)
```
**The response content cannot be parsed because the Internet Explorer engine is not available**
- Use This command:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;$s = Invoke-WebRequest https://raw.githubusercontent.com/noobscode/LetsEncryptRemediation/main/runbook.ps1 -UseBasicParsing;Invoke-Expression $($s.Content)
```
