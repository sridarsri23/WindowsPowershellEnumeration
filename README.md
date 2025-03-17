# Windows Enumeration & Weakness Identification Script

## Overview
This PowerShell script is designed to enumerate Windows system details and identify potential security weaknesses. The script collects information about:
- System Information
- User Accounts & Administrator Privileges
- Installed Applications
- Running Services
- Network Configuration & Open Ports
- Password Policy & Firewall Status
- Antivirus Status
- Active Directory Enumeration (if applicable)
- Weak Encryption Protocols (SMB, TLS/SSL, Hashing)
- Misconfigurations and Common Vulnerabilities

The results are saved in a structured report for further analysis.

## Installation & Usage

### **1. Clone the Repository**
Clone the repository to your local machine:
```sh
 git clone https://github.com/sridarsri23/WindowsPowershellEnumeration.git
 cd WindowsPowershellEnumeration
```

### **2. Save the Script**
Ensure the script is saved as:
```
Windows_Enumeration.ps1
```

### **3. Adjust PowerShell Execution Policy**
To allow execution of PowerShell scripts, run:
```powershell
Set-ExecutionPolicy Unrestricted -Scope Process
```
This temporarily allows script execution for the current session.

### **4. Run the Script**
Execute the script in PowerShell:
```powershell
.\Windows_Enumeration.ps1
```
This will generate a report and save it as:
```
C:\Windows_Enumeration_Report.txt
```

### **5. Review the Output**
Once execution is complete, open the generated file for analysis:
```sh
notepad C:\Windows_Enumeration_Report.txt
```

## **Example Usage Scenarios**
- Security teams conducting **internal security audits**
- IT administrators **assessing system configurations**
- Penetration testers **identifying potential weaknesses**
- Incident response teams **collecting forensic evidence**
- Compliance checks for security frameworks (CIS, NIST, ISO 27001)

## **Additional Features**
- **Logging:** Generates detailed logs for debugging and documentation
- **Automation Ready:** Can be integrated into security monitoring pipelines
- **Extensible:** Easily modifiable for additional enumeration checks

## **Contributing**
Feel free to submit issues or contribute improvements via Pull Requests.

## **License**
This project is licensed under the MIT License. See `LICENSE` for details.

