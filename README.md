# Windows Fail2Ban 

This Powershell script looks for failed authorization events, parses the IP from those events and adds them into a new Windows Firewall rule.

I would recommend to add this script into a Windows sheduled task at intervals about 10-15 minutes.
