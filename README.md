# AD ADMIN TOOL — PowerShell Active Directory Automation (v3)

A secure and modern PowerShell tool for managing Active Directory accounts remotely over WinRM.  
Supports password resets, unlocking, disabling, credential testing, automatic domain detection, encrypted credential storage, and detailed logging.

> ⚠ **Disclaimer:**  
> Tested **only in a home lab environment**.  
> Never used in production. Validate behavior before real-world use.

---

## 🔧 Features

- Remote AD management via WinRM (supports HTTP/HTTPS)
- Encrypted admin credential storage (DPAPI)
- Auto-generated folders for logs and cache
- Reads servers from `servers.txt` in format:  
  `NAME|IP|PORT`
- Clean server selection menu:  
  `DC01 (192.168.56.101:5985)`
- Automatic Active Directory domain detection
- User lookup with AD attribute details
- Password reset with secure random generator
- "Must change password at next logon" option
- Optional password verification using .NET authentication
- Unlock / Disable / Credential test actions
- Centralized audit log with timestamps and status codes
- Robust error handling and validation

---

## 🚀 Quick Usage

### **1. Prepare files**
Place the script in a folder. It will auto-create:

```
/cache  
/logs  
/cache/.map  
```

---

### **2. Create `servers.txt`**

Example:

```
DC01|192.168.56.101|5985
DC02|192.168.56.102|5986
```

Each line:  
`ServerName | IP Address | WinRM Port`

---

### **3. Run the script**

```powershell
.\Reset-Password-v3I.ps1
```

You will:

1. Select a server from the menu  
2. Enter admin credentials (saved securely for future use)  
3. Search for a user  
4. Choose one of the actions:
   - Reset password + unlock  
   - Unlock account  
   - Disable account  
   - Test user credentials  

All operations are logged automatically.

---

## 📁 Logs

Audit entries are stored in:

```
logs/audit.log
```

Format:

```
timestamp | adminUser | server | targetUser | action | status | details
```

---

## 📬 Author

Created by **Sofron Vasile Stelian**  

