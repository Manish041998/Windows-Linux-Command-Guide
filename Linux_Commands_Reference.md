# Essential Linux Commands Reference

## System Information

```bash
# System details
uname -a                      # Kernel and system info
hostname                      # Computer name
hostnamectl                   # System hostname and related info
whoami                        # Current user
id                            # User ID and group IDs
uptime                        # System uptime and load
cat /etc/os-release           # Distribution information
lsb_release -a                # Distribution info (if available)

# Hardware info
lscpu                         # CPU information
lsmem                         # Memory information
free -h                       # RAM usage (human readable)
df -h                         # Disk space usage
lsblk                         # List block devices
lspci                         # PCI devices
lsusb                         # USB devices
dmidecode                     # Hardware details (requires root)
hwinfo                        # Detailed hardware info (if installed)
```

## User Management

```bash
# User operations
useradd [username]            # Add user
useradd -m -s /bin/bash [user]  # Add user with home dir and shell
userdel [username]            # Delete user
userdel -r [username]         # Delete user and home directory
usermod -aG [group] [user]    # Add user to group
passwd [username]             # Change user password

# User information
who                           # Logged in users
w                             # Who is logged in and what they're doing
last                          # Login history
lastlog                       # Last login for all users
finger [username]             # User information (if installed)

# Group management
groupadd [groupname]          # Create group
groupdel [groupname]          # Delete group
groups [username]             # Show user's groups
cat /etc/passwd               # List all users
cat /etc/group                # List all groups
getent passwd                 # Query user database
getent group                  # Query group database
```

## Process Management

```bash
# Process listing
ps aux                        # All running processes
ps -ef                        # All processes (different format)
pstree                        # Process tree
top                           # Real-time process viewer
htop                          # Interactive process viewer (if installed)
atop                          # Advanced system monitor (if installed)

# Process control
kill [PID]                    # Send SIGTERM to process
kill -9 [PID]                 # Force kill (SIGKILL)
killall [process_name]        # Kill all processes by name
pkill [pattern]               # Kill processes matching pattern
pgrep [pattern]               # Find process IDs by pattern

# Background jobs
jobs                          # List background jobs
bg [job_id]                   # Resume job in background
fg [job_id]                   # Bring job to foreground
nohup [command] &             # Run command immune to hangups

# Process priority
nice -n [priority] [command]  # Run with priority (-20 to 19)
renice [priority] -p [PID]    # Change priority of running process
```

## Service Management

```bash
# SystemD (modern systems)
systemctl status [service]    # Service status
systemctl start [service]     # Start service
systemctl stop [service]      # Stop service
systemctl restart [service]   # Restart service
systemctl enable [service]    # Enable at boot
systemctl disable [service]   # Disable at boot
systemctl list-units --type=service  # List all services
systemctl daemon-reload       # Reload systemd configuration

# Service logs
journalctl -u [service]       # View service logs
journalctl -f                 # Follow all logs
journalctl -b                 # Logs since last boot
journalctl --since "1 hour ago"  # Recent logs

# Init.d (older systems)
service [service] status      # Service status
service [service] start       # Start service
service [service] stop        # Stop service
/etc/init.d/[service] restart # Restart service
chkconfig --list              # List services (Red Hat)
update-rc.d [service] enable  # Enable service (Debian)
```

## Network Commands

```bash
# Network configuration
ip addr show                  # Show IP addresses
ip link show                  # Show network interfaces
ip route show                 # Show routing table
ifconfig                      # Network interfaces (deprecated, use ip)
ifconfig eth0 up/down         # Enable/disable interface

# Network connectivity
ping [host]                   # Test connectivity
ping -c 4 [host]              # Ping 4 times
traceroute [host]             # Trace route to host
mtr [host]                    # Continuous traceroute
curl [url]                    # Fetch URL content
wget [url]                    # Download file
nc -zv [host] [port]          # Test port connectivity (netcat)
telnet [host] [port]          # Test port connectivity

# DNS
nslookup [domain]             # DNS lookup
dig [domain]                  # DNS query (more detailed)
host [domain]                 # DNS lookup
cat /etc/resolv.conf          # DNS servers

# Network connections
netstat -tuln                 # All listening ports
netstat -tunap                # All connections with PIDs
ss -tuln                      # Socket statistics (newer)
ss -tunap                     # All connections with PIDs
lsof -i                       # Network connections by process
lsof -i :80                   # What's using port 80

# Network configuration files
cat /etc/network/interfaces   # Network config (Debian)
cat /etc/sysconfig/network-scripts/ifcfg-eth0  # Network config (Red Hat)
cat /etc/hosts                # Host file
cat /etc/hostname             # Hostname

# ARP and routing
arp -a                        # ARP table
ip neigh show                 # ARP table (newer)
route -n                      # Routing table
ip route add [network] via [gateway]  # Add route

# Firewall
iptables -L -n -v             # List firewall rules
iptables -A INPUT -p tcp --dport 22 -j ACCEPT  # Allow SSH
ufw status                    # UFW firewall status (Ubuntu)
ufw allow 22/tcp              # Allow port with UFW
firewall-cmd --list-all       # Firewalld status (Red Hat)
```

## File System Operations

```bash
# Navigation
ls                            # List files
ls -la                        # List all files with details
ls -lh                        # Human readable sizes
cd [directory]                # Change directory
pwd                           # Print working directory
tree                          # Directory tree (if installed)
find / -name [filename]       # Find file by name

# File operations
cp [source] [dest]            # Copy file
cp -r [source] [dest]         # Copy directory recursively
mv [source] [dest]            # Move/rename file
rm [file]                     # Remove file
rm -rf [directory]            # Remove directory recursively (dangerous!)
mkdir [directory]             # Create directory
mkdir -p [path/to/dir]        # Create nested directories
rmdir [directory]             # Remove empty directory

# File viewing
cat [file]                    # Display file content
less [file]                   # Page through file
more [file]                   # Page through file
head [file]                   # First 10 lines
head -n 20 [file]             # First 20 lines
tail [file]                   # Last 10 lines
tail -f [file]                # Follow file updates (logs)
tail -n 50 [file]             # Last 50 lines

# File searching
grep [pattern] [file]         # Search in file
grep -r [pattern] [directory] # Recursive search
grep -i [pattern] [file]      # Case-insensitive search
grep -v [pattern] [file]      # Inverse match (exclude)
find [path] -name [pattern]   # Find files by name
find [path] -type f -mtime -7 # Files modified in last 7 days
locate [filename]             # Fast file search (uses database)
updatedb                      # Update locate database

# File editing
nano [file]                   # Simple text editor
vi [file]                     # Vi editor
vim [file]                    # Vim editor
sed 's/old/new/g' [file]      # Stream editor (replace text)
awk '{print $1}' [file]       # Text processing
```

## File Permissions & Ownership

```bash
# Permissions
chmod 755 [file]              # rwxr-xr-x permissions
chmod u+x [file]              # Add execute for user
chmod -R 644 [directory]      # Recursive permission change
chmod a+r [file]              # Add read for all

# Ownership
chown [user] [file]           # Change owner
chown [user]:[group] [file]   # Change owner and group
chown -R [user] [directory]   # Recursive ownership change
chgrp [group] [file]          # Change group

# View permissions
ls -l [file]                  # Long listing with permissions
stat [file]                   # Detailed file info
getfacl [file]                # Get ACL (Access Control List)
setfacl -m u:[user]:rwx [file]  # Set ACL
```

## Disk Management

```bash
# Disk usage
df -h                         # Disk space usage
df -i                         # Inode usage
du -sh [directory]            # Directory size
du -h --max-depth=1           # Size of subdirectories
ncdu                          # Interactive disk usage (if installed)

# Disk partitions
fdisk -l                      # List disk partitions (root)
parted -l                     # Partition info (root)
lsblk                         # Block device info
blkid                         # Block device attributes

# Mounting
mount                         # Show mounted filesystems
mount [device] [mountpoint]   # Mount filesystem
umount [mountpoint]           # Unmount filesystem
cat /etc/fstab                # Filesystem table (auto-mount)

# Filesystem operations
mkfs.ext4 [device]            # Create ext4 filesystem (root)
fsck [device]                 # Check and repair filesystem (root)
e2fsck [device]               # Check ext filesystem (root)
```

## Package Management

```bash
# Debian/Ubuntu (APT)
apt update                    # Update package list
apt upgrade                   # Upgrade packages
apt install [package]         # Install package
apt remove [package]          # Remove package
apt search [package]          # Search for package
apt list --installed          # List installed packages
dpkg -l                       # List installed packages
dpkg -i [package.deb]         # Install .deb package
dpkg -r [package]             # Remove package

# Red Hat/CentOS/Fedora (YUM/DNF)
yum update                    # Update packages
yum install [package]         # Install package
yum remove [package]          # Remove package
yum search [package]          # Search for package
yum list installed            # List installed packages
rpm -qa                       # List installed packages
rpm -ivh [package.rpm]        # Install .rpm package
rpm -e [package]              # Remove package

# DNF (newer Red Hat systems)
dnf update                    # Update packages
dnf install [package]         # Install package
dnf remove [package]          # Remove package
dnf search [package]          # Search for package
dnf list installed            # List installed packages

# Arch Linux (pacman)
pacman -Syu                   # Update system
pacman -S [package]           # Install package
pacman -R [package]           # Remove package
pacman -Ss [package]          # Search for package
pacman -Q                     # List installed packages
```

## System Logs

```bash
# Log files
tail -f /var/log/syslog       # Follow system log (Debian)
tail -f /var/log/messages     # Follow system log (Red Hat)
tail -f /var/log/auth.log     # Authentication log (Debian)
tail -f /var/log/secure       # Authentication log (Red Hat)
cat /var/log/kern.log         # Kernel log
dmesg                         # Kernel ring buffer
dmesg | grep -i error         # Kernel errors

# SystemD journal
journalctl                    # All journal entries
journalctl -f                 # Follow journal
journalctl -u [service]       # Service-specific logs
journalctl -b                 # Logs since last boot
journalctl --since "1 hour ago"  # Recent logs
journalctl -p err             # Error priority logs only
journalctl -k                 # Kernel messages
```

## Security & Authentication

```bash
# User authentication
sudo [command]                # Run command as root
sudo -i                       # Interactive root shell
su [username]                 # Switch user
su -                          # Switch to root
visudo                        # Edit sudoers file safely

# SSH
ssh [user]@[host]             # SSH connection
ssh -p [port] [user]@[host]   # SSH on specific port
ssh-keygen                    # Generate SSH key pair
ssh-copy-id [user]@[host]     # Copy SSH key to remote
scp [file] [user]@[host]:[path]  # Secure copy
sftp [user]@[host]            # Secure FTP

# File integrity
md5sum [file]                 # MD5 hash
sha256sum [file]              # SHA256 hash
sha512sum [file]              # SHA512 hash

# SELinux (Red Hat)
getenforce                    # SELinux status
setenforce 0|1                # Disable/enable SELinux
sestatus                      # SELinux status details
ls -Z [file]                  # SELinux context
chcon [context] [file]        # Change SELinux context

# AppArmor (Ubuntu)
aa-status                     # AppArmor status
aa-enforce [profile]          # Enforce profile
aa-complain [profile]         # Complain mode
```

## Scheduled Tasks

```bash
# Cron
crontab -l                    # List cron jobs
crontab -e                    # Edit cron jobs
crontab -r                    # Remove all cron jobs
cat /etc/crontab              # System crontab
ls /etc/cron.d/               # Additional cron files
ls /etc/cron.daily/           # Daily cron scripts

# At (one-time scheduled tasks)
at 10:00 PM                   # Schedule command for 10 PM
atq                           # List scheduled at jobs
atrm [job_id]                 # Remove at job

# SystemD timers
systemctl list-timers         # List all timers
systemctl status [timer]      # Timer status
```

## Performance Monitoring

```bash
# CPU and memory
top                           # Real-time system monitor
htop                          # Interactive process viewer
vmstat 5                      # Virtual memory stats every 5 sec
mpstat                        # CPU statistics
iostat                        # I/O statistics
sar                           # System activity reporter

# Disk I/O
iotop                         # I/O monitor by process (root)
iftop                         # Network bandwidth monitor (root)

# System load
uptime                        # Load average
cat /proc/loadavg             # Load average file
w                             # Load and users

# Memory
free -h                       # Memory usage
cat /proc/meminfo             # Detailed memory info
vmstat -s                     # Memory statistics
```

## Archive & Compression

```bash
# Tar archives
tar -czf archive.tar.gz [dir]     # Create gzip compressed tar
tar -xzf archive.tar.gz           # Extract gzip tar
tar -cjf archive.tar.bz2 [dir]    # Create bzip2 compressed tar
tar -xjf archive.tar.bz2          # Extract bzip2 tar
tar -tf archive.tar               # List tar contents

# Compression
gzip [file]                       # Compress file (creates .gz)
gunzip [file.gz]                  # Decompress gzip
bzip2 [file]                      # Compress file (creates .bz2)
bunzip2 [file.bz2]                # Decompress bzip2
zip -r archive.zip [dir]          # Create zip archive
unzip archive.zip                 # Extract zip archive

# Advanced
xz [file]                         # Compress with xz (best compression)
unxz [file.xz]                    # Decompress xz
7z a archive.7z [files]           # Create 7z archive
7z x archive.7z                   # Extract 7z archive
```

## Text Processing

```bash
# Stream editing
sed 's/old/new/g' file            # Replace text
sed -i 's/old/new/g' file         # Replace in-place
sed -n '10,20p' file              # Print lines 10-20

# AWK
awk '{print $1}' file             # Print first column
awk -F: '{print $1}' /etc/passwd  # Print with custom delimiter
awk '$3 > 100' file               # Print lines where column 3 > 100

# Sorting and filtering
sort file                         # Sort lines
sort -n file                      # Numeric sort
sort -r file                      # Reverse sort
uniq file                         # Remove duplicate lines
sort file | uniq                  # Sort and remove duplicates
sort file | uniq -c               # Count occurrences
cut -d: -f1 /etc/passwd           # Cut fields
tr 'a-z' 'A-Z' < file             # Translate characters (uppercase)

# Column manipulation
column -t file                    # Format into columns
paste file1 file2                 # Merge files line by line
join file1 file2                  # Join files on common field

# Word count
wc file                           # Lines, words, characters
wc -l file                        # Count lines
wc -w file                        # Count words
wc -c file                        # Count bytes
```

## Environment & Variables

```bash
# Environment variables
env                           # List all environment variables
printenv                      # List all environment variables
echo $PATH                    # Print PATH variable
export VAR=value              # Set environment variable
unset VAR                     # Unset variable

# Shell configuration
cat ~/.bashrc                 # Bash configuration
cat ~/.bash_profile           # Bash login configuration
source ~/.bashrc              # Reload bash configuration
cat /etc/environment          # System-wide environment
cat /etc/profile              # System-wide profile

# History
history                       # Command history
history | grep [command]      # Search history
!123                          # Run command number 123
!!                            # Run last command
!$                            # Last argument of previous command
```

## System Boot & Shutdown

```bash
# Shutdown and reboot
shutdown -h now               # Shutdown immediately
shutdown -h +10               # Shutdown in 10 minutes
shutdown -r now               # Reboot immediately
reboot                        # Reboot system
poweroff                      # Power off system
halt                          # Halt system
init 0                        # Shutdown (runlevel 0)
init 6                        # Reboot (runlevel 6)

# Boot information
dmesg                         # Boot messages
last reboot                   # Reboot history
uptime                        # How long system has been running

# Runlevels/Targets
systemctl get-default         # Get default target
systemctl set-default multi-user.target  # Set default target
systemctl isolate rescue.target  # Switch to rescue mode
```

## Kernel & Modules

```bash
# Kernel information
uname -r                      # Kernel version
uname -a                      # All kernel info
cat /proc/version             # Kernel version
cat /proc/cmdline             # Kernel boot parameters

# Kernel modules
lsmod                         # List loaded modules
modinfo [module]              # Module information
modprobe [module]             # Load module
modprobe -r [module]          # Remove module
rmmod [module]                # Remove module
insmod [module.ko]            # Insert module

# Kernel parameters
sysctl -a                     # All kernel parameters
sysctl [parameter]            # View parameter
sysctl -w [parameter]=[value] # Set parameter
cat /etc/sysctl.conf          # Persistent kernel parameters
```

## Remote File Transfer

```bash
# SCP (Secure Copy)
scp [file] [user]@[host]:[path]      # Copy to remote
scp [user]@[host]:[file] [local]     # Copy from remote
scp -r [dir] [user]@[host]:[path]    # Copy directory
scp -P [port] [file] [user]@[host]:[path]  # Custom port

# Rsync (efficient synchronization)
rsync -avz [source] [dest]           # Archive, verbose, compress
rsync -avz [source] [user]@[host]:[dest]  # Remote sync
rsync -avz --delete [source] [dest]  # Sync and delete extras
rsync -avz --progress [source] [dest]  # Show progress

# SFTP
sftp [user]@[host]                   # Start SFTP session
# Within SFTP: get [file], put [file], ls, cd, etc.
```

## Process Information

```bash
# Process details
ps aux | grep [process]       # Find process
pidof [process]               # Get PID of process
pgrep [pattern]               # Find PIDs by pattern
lsof -p [PID]                 # Files opened by process
lsof -u [user]                # Files opened by user
lsof -i :80                   # What's using port 80
strace -p [PID]               # Trace system calls (debugging)
ltrace -p [PID]               # Trace library calls

# Resource limits
ulimit -a                     # Show all limits
ulimit -n                     # File descriptor limit
ulimit -u                     # Max user processes
```

## System Hardware Info

```bash
# Hardware detection
lshw                          # List hardware (root)
lshw -short                   # Short hardware list
lspci                         # PCI devices
lsusb                         # USB devices
lscpu                         # CPU info
lsblk                         # Block devices
hwinfo                        # Hardware info (if installed)

# Device information
cat /proc/cpuinfo             # CPU details
cat /proc/meminfo             # Memory details
cat /proc/devices             # Device drivers
cat /proc/partitions          # Partition info
```

## Miscellaneous Important Commands

```bash
# Date and time
date                          # Current date and time
timedatectl                   # Time and date control
ntpdate [server]              # Sync time with NTP server
hwclock                       # Hardware clock

# System control
systemctl reboot              # Reboot system
systemctl poweroff            # Power off system
systemctl suspend             # Suspend system
systemctl hibernate           # Hibernate system

# Aliases
alias                         # List aliases
alias ll='ls -la'             # Create alias
unalias ll                    # Remove alias

# Screen/Tmux (terminal multiplexer)
screen                        # Start screen session
screen -ls                    # List screen sessions
screen -r [session]           # Reattach to session
tmux                          # Start tmux session
tmux ls                       # List tmux sessions
tmux attach -t [session]      # Attach to session

# System information tools
inxi -F                       # System info (if installed)
neofetch                      # System info with logo (if installed)
screenfetch                   # System info (if installed)
```

## Security Tools & Commands

```bash
# Port scanning
nmap [host]                   # Basic scan
nmap -sS [host]               # SYN scan
nmap -p 1-65535 [host]        # Scan all ports
nmap -A [host]                # Aggressive scan (OS, version)

# Network monitoring
tcpdump -i eth0               # Capture packets on eth0
tcpdump -i eth0 port 80       # Capture port 80 traffic
wireshark                     # GUI packet analyzer

# System auditing
auditctl -l                   # List audit rules
ausearch -m [message_type]    # Search audit logs
aureport                      # Audit report

# Security scanning
lynis audit system            # Security audit (if installed)
rkhunter --check              # Rootkit hunter (if installed)
chkrootkit                    # Check for rootkits (if installed)

# Fail2Ban
fail2ban-client status        # Fail2Ban status
fail2ban-client status sshd   # SSH jail status
```

---

## Pro Tips for Cybersecurity

**Essential for threat hunting:**
- `journalctl -u [service] --since "1 hour ago"` - Recent service logs
- `last -f /var/log/wtmp` - Login history
- `ausearch -m USER_LOGIN -ts recent` - Recent logins (if auditd enabled)
- `grep "Failed password" /var/log/auth.log` - Failed login attempts
- `netstat -tunap | grep ESTABLISHED` - Active network connections
- `find / -type f -mtime -1` - Files modified in last 24 hours
- `ps aux --sort=-%cpu | head` - Top CPU consumers

**Command combinations:**
```bash
# Find large files
find / -type f -size +100M 2>/dev/null

# Find SUID files (potential privilege escalation)
find / -perm -4000 -type f 2>/dev/null

# Active network connections with process names
netstat -tunap | grep ESTABLISHED

# Monitor real-time log
tail -f /var/log/auth.log | grep --line-buffered "Failed"

# Count login attempts by IP
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn
```
