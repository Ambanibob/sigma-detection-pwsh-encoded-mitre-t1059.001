index=winlogbeat OR index=sysmon
(Image="\powershell.exe")
(CommandLine="-enc*" OR (CommandLine="Invoke-WebRequest" CommandLine="http") OR (CommandLine="iex" CommandLine="http"))
| where NOT (ParentImage="\System32\services.exe" OR ParentImage="\svchost.exe")
| table _time, User, Image, ParentImage, CommandLine

# sigma-detection-pwsh-encoded-mitre-t1059.001
