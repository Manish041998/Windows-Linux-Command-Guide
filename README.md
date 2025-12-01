# Windows-Linux-Command-Guide

> Essential commands for Windows and Linux system administration and security operations.

---

## 📋 Contents

- [Windows Commands](Essential_Windows_Commands.md)
- [Linux Commands](Linux_Commands_Reference.md)

---

## 🎯 About

A comprehensive reference guide for system administrators and cybersecurity professionals working across Windows and Linux environments.

**Use cases:**
- Security operations and threat hunting
- System administration
- Incident response
- Daily IT operations

---

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/Manish041998/Windows-Linux-Command-Guide.git

# Browse the guides
- Windows: Essential_Windows_Commands.md
- Linux: Linux_Commands_Reference.md
```

---

## 📚 What's Inside

### Windows
- System information and hardware
- User and access management
- Process and service management
- Network configuration
- Security and auditing
- PowerShell essentials
- WMIC commands

### Linux
- System information and hardware
- User and group management
- Process control
- Service management (SystemD)
- Network configuration
- Package management
- Security tools

---

## 💡 Quick Examples

**Check active connections:**
```powershell
# Windows
netstat -ano | findstr ESTABLISHED

# Linux
netstat -tunap | grep ESTABLISHED
```

**View recent logs:**
```powershell
# Windows
Get-EventLog -LogName Security -Newest 100

# Linux
journalctl -n 100
```

---

## 📝 License

MIT License

---

## 📞 Contact

**Issues**: [GitHub Issues](https://github.com/Manish041998/Windows-Linux-Command-Guide/issues)

---

**⭐ Star this repo if you find it helpful!**

---

<sub>Last updated: December 2025</sub>
