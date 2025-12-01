# Essential Windows Commands Reference

## System Information

```powershell
# System details
systeminfo                    # Detailed system information
hostname                      # Computer name
whoami                        # Current user
whoami /all                   # User + groups + privileges
ver                           # Windows version
winver                        # Windows version (GUI)
msinfo32                      # System Information GUI

# Hardware info
wmic cpu get name             # CPU information
wmic memorychip get capacity  # RAM details
wmic diskdrive get size,model # Disk information
Get-ComputerInfo              # PowerShell: comprehensive system info
```

## User Management

```powershell
# Local users
net user                      # List all users
net user [username]           # User details
net user [username] [password] /add    # Add user
net user [username] /delete   # Delete user
net user [username] /active:yes|no     # Enable/disable user

# Groups
net localgroup                # List groups
net localgroup Administrators # List admin group members
net localgroup Administrators [username] /add  # Add to admin group

# PowerShell alternatives
Get-LocalUser                 # List users
Get-LocalGroup                # List groups
Get-LocalGroupMember Administrators  # Group members
```

## Process Management

```powershell
# Task management
tasklist                      # List running processes
tasklist /svc                 # Processes with services
taskkill /PID [pid]          # Kill by process ID
taskkill /IM [name.exe] /F   # Kill by name (force)

# PowerShell
Get-Process                   # List processes
Get-Process | Sort-Object CPU -Descending  # Sort by CPU
Stop-Process -Name [name]     # Stop process
Stop-Process -Id [pid]        # Stop by PID

# WMIC
wmic process list brief       # Process list
wmic process where name="chrome.exe" delete  # Kill process
wmic process get processid,name,executablepath  # Detailed info
```

## Service Management

```powershell
# Services
sc query                      # List services
sc query [service]            # Service status
sc start [service]            # Start service
sc stop [service]             # Stop service
sc config [service] start=auto|disabled  # Configure startup

# Net commands
net start                     # List running services
net start [service]           # Start service
net stop [service]            # Stop service

# PowerShell
Get-Service                   # List all services
Get-Service | Where-Object {$_.Status -eq "Running"}
Start-Service [name]          # Start service
Stop-Service [name]           # Stop service
Restart-Service [name]        # Restart service

# WMIC
wmic service list brief       # List services
wmic service where name="wuauserv" get state  # Service state
```

## Network Commands

```powershell
# Network configuration
ipconfig                      # IP configuration
ipconfig /all                 # Detailed network info
ipconfig /flushdns            # Clear DNS cache
ipconfig /release             # Release DHCP IP
ipconfig /renew               # Renew DHCP IP

# Network connections
netstat -ano                  # All connections with PIDs
netstat -anob                 # Include process names (admin required)
netstat -r                    # Routing table

# Testing connectivity
ping [host]                   # Test connectivity
tracert [host]                # Trace route
pathping [host]               # Combines ping + tracert
nslookup [domain]             # DNS lookup
telnet [host] [port]          # Test port connectivity

# Network shares
net share                     # List shares
net use                       # List mapped drives
net use Z: \\server\share     # Map network drive
net use Z: /delete            # Remove mapped drive

# PowerShell networking
Get-NetIPAddress              # IP addresses
Get-NetAdapter                # Network adapters
Test-NetConnection [host]     # Test connectivity
Test-NetConnection [host] -Port [port]  # Test specific port
Get-NetTCPConnection          # TCP connections
```

## File System Operations

```powershell
# Navigation
dir                           # List directory contents
cd [path]                     # Change directory
tree                          # Directory tree
where [command]               # Find command location

# File operations
copy [source] [dest]          # Copy file
xcopy [source] [dest] /E      # Copy directory tree
robocopy [source] [dest] /E   # Robust copy (better than xcopy)
move [source] [dest]          # Move file
del [file]                    # Delete file
rmdir [dir] /S                # Delete directory recursively

# File attributes
attrib                        # Show file attributes
attrib +h [file]              # Hide file
attrib -h [file]              # Unhide file
attrib +r [file]              # Make read-only

# PowerShell file operations
Get-ChildItem                 # List items (like ls)
Get-ChildItem -Recurse        # Recursive listing
Copy-Item [source] [dest]     # Copy
Move-Item [source] [dest]     # Move
Remove-Item [path]            # Delete
Get-Content [file]            # Read file content
Set-Content [file] [content]  # Write file
```

## Disk Management

```powershell
# Disk info
diskpart                      # Disk partition tool (interactive)
chkdsk C: /F                  # Check and fix disk errors
defrag C:                     # Defragment disk

# PowerShell
Get-Disk                      # List disks
Get-Volume                    # List volumes
Get-Partition                 # List partitions

# WMIC
wmic logicaldisk get name,size,freespace  # Disk space
wmic diskdrive get model,size,status      # Physical drives
```

## Security & Permissions

```powershell
# File permissions
icacls [file]                 # View permissions
icacls [file] /grant user:(F) # Grant full control
icacls [file] /remove user    # Remove permissions
takeown /F [file]             # Take ownership

# User rights
runas /user:[user] [command]  # Run as different user

# PowerShell
Get-Acl [path]                # Get permissions
Set-Acl [path] [acl]          # Set permissions
```

## Event Logs & Auditing

```powershell
# Event logs
wevtutil el                   # List event logs
wevtutil qe System /c:10 /rd:true /f:text  # Query last 10 events

# PowerShell
Get-EventLog -LogName System -Newest 100   # Get events
Get-WinEvent -LogName Security -MaxEvents 50  # Security events
Get-EventLog -LogName Application -EntryType Error  # Filter by type
```

## Registry Operations

```powershell
# Registry commands
reg query [key]               # Query registry key
reg add [key] /v [name] /d [data]  # Add value
reg delete [key] /v [name]    # Delete value

# PowerShell
Get-ItemProperty [path]       # Get registry value
Set-ItemProperty [path] -Name [name] -Value [value]  # Set value
New-Item [path]               # Create key
Remove-Item [path]            # Delete key
```

## Windows Update

```powershell
# Windows Update
wuauclt /detectnow            # Check for updates (older Windows)
wuauclt /updatenow            # Install updates (older Windows)

# PowerShell (Windows 10+)
Get-WindowsUpdate             # Check updates (requires module)
Install-WindowsUpdate         # Install updates
Get-HotFix                    # List installed updates
```

## Scheduled Tasks

```powershell
# Task scheduler
schtasks                      # List scheduled tasks
schtasks /query /fo LIST /v   # Detailed list
schtasks /create /tn [name] /tr [command] /sc [schedule]  # Create task
schtasks /delete /tn [name]   # Delete task
schtasks /run /tn [name]      # Run task now

# PowerShell
Get-ScheduledTask             # List tasks
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"}
Start-ScheduledTask [name]    # Run task
```

## PowerShell Specific

```powershell
# Execution policy
Get-ExecutionPolicy           # Check policy
Set-ExecutionPolicy RemoteSigned  # Set policy (admin)

# Module management
Get-Module                    # List loaded modules
Get-Module -ListAvailable     # List available modules
Import-Module [name]          # Load module

# Help system
Get-Help [command]            # Get help
Get-Command                   # List all commands
Get-Command -Verb Get         # Commands starting with Get
Get-Command *network*         # Search commands

# Object pipeline
Get-Process | Select-Object Name, CPU | Sort-Object CPU -Descending
Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object Name
```

## WMIC Commands (Comprehensive)

```powershell
# System information
wmic bios get serialnumber    # BIOS serial
wmic computersystem get model,manufacturer  # System model
wmic os get caption,version,buildnumber     # OS version

# Hardware
wmic cpu get name,numberofcores,maxclockspeed  # CPU info
wmic memorychip get capacity,speed             # RAM info
wmic diskdrive get model,size,interfacetype    # Disk info
wmic baseboard get product,manufacturer        # Motherboard
wmic nic get name,macaddress                   # Network adapters

# Software
wmic product get name,version              # Installed software
wmic startup list brief                    # Startup programs
wmic qfe list                              # Installed patches

# Processes & Services
wmic process list brief                    # Processes
wmic service list brief                    # Services
wmic process where "name='chrome.exe'" get processid,commandline

# User info
wmic useraccount get name,sid              # Users and SIDs
wmic netlogin get name,lastlogon           # Logon info

# Advanced queries
wmic process where "ProcessId=[pid]" get commandline  # Process command line
wmic process where "name like '%chrome%'" delete      # Kill matching processes
wmic service where "state='running'" get name,pathname  # Running services paths
```

## System Administration

```powershell
# Shutdown/Restart
shutdown /s /t 0              # Shutdown immediately
shutdown /r /t 0              # Restart immediately
shutdown /a                   # Abort shutdown
shutdown /s /t 300            # Shutdown in 5 minutes

# System file checker
sfc /scannow                  # Scan and repair system files
DISM /Online /Cleanup-Image /RestoreHealth  # Repair Windows image

# Driver management
driverquery                   # List installed drivers
pnputil /enum-drivers         # Enumerate drivers

# PowerShell
Get-PnpDevice                 # List devices
Get-PnpDevice -Class Display  # Filter by class
```

## BitLocker

```powershell
manage-bde -status            # BitLocker status
manage-bde -on C: -RecoveryPassword  # Enable BitLocker
manage-bde -protectors -add C: -TPM  # Add TPM protector
manage-bde -lock C:           # Lock drive
manage-bde -unlock C: -RecoveryPassword [key]  # Unlock
```

## Firewall

```powershell
# Netsh firewall (older)
netsh advfirewall show allprofiles       # Firewall status
netsh advfirewall set allprofiles state on|off  # Enable/disable
netsh advfirewall firewall show rule name=all   # List rules

# PowerShell
Get-NetFirewallProfile        # Firewall profiles
Get-NetFirewallRule           # Firewall rules
New-NetFirewallRule -DisplayName "Allow Port" -Direction Inbound -LocalPort 8080 -Protocol TCP -Action Allow
```

## Certificate Management

```powershell
certutil -store my            # List certificates in personal store
certutil -hashfile [file] SHA256  # Get file hash
certmgr.msc                   # Certificate Manager GUI
```

## Performance & Monitoring

```powershell
perfmon                       # Performance Monitor
resmon                        # Resource Monitor
taskmgr                       # Task Manager

# PowerShell
Get-Counter                   # Performance counters
Get-Counter '\Processor(_Total)\% Processor Time'  # CPU usage
```

## Remote Management

```powershell
# Remote Desktop
mstsc                         # Remote Desktop Connection

# PowerShell Remoting
Enable-PSRemoting             # Enable remoting (admin)
Enter-PSSession -ComputerName [host]  # Interactive session
Invoke-Command -ComputerName [host] -ScriptBlock {Get-Process}  # Remote command

# WinRM
winrm quickconfig             # Configure WinRM
winrm get winrm/config        # View WinRM config
```

## Group Policy

```powershell
gpupdate /force               # Force group policy update
gpresult /r                   # Display applied policies
gpresult /h report.html       # Generate HTML report
gpedit.msc                    # Group Policy Editor (Pro/Enterprise)
```

## Package Management (Modern Windows)

```powershell
# Windows Package Manager (winget)
winget search [app]           # Search for app
winget install [app]          # Install app
winget list                   # List installed apps
winget upgrade --all          # Update all apps

# PowerShell Package Management
Get-Package                   # List installed packages
Install-Package [name]        # Install package
Uninstall-Package [name]      # Uninstall package
```

## Quick Diagnostics

```powershell
# System health
sfc /scannow                  # System file checker
DISM /Online /Cleanup-Image /ScanHealth    # Check image health
chkdsk C: /F /R               # Check disk with repair

# Network diagnostics
netsh winsock reset           # Reset Winsock
netsh int ip reset            # Reset TCP/IP
ipconfig /registerdns         # Register DNS

# Performance
perfmon /report               # Generate system diagnostics report
```

---

## Pro Tips

**For cybersecurity work:**
- Always run `wmic` commands with specific queries to avoid information overload
- Use `Get-WinEvent` for security log analysis (better than `Get-EventLog`)
- Combine commands with `| Select-Object` to filter output
- Use `-ComputerName` parameter in PowerShell for remote queries
- Save `wmic` output to CSV: `wmic process list brief /format:csv > processes.csv`

**Command priority for your work:**
1. Event log queries (`Get-WinEvent`, `wevtutil`)
2. Network monitoring (`netstat`, `Get-NetTCPConnection`)
3. Process investigation (`Get-Process`, `wmic process`)
4. User activity (`Get-EventLog Security`, `net user`)
5. Service monitoring (`Get-Service`, `sc query`)
