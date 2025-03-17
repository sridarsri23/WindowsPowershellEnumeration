# PowerShell Script for Windows Enumeration & Weakness Identification

# Define Output File
$OutputFile = "C:\Windows_Enumeration_Report.txt"

# Function to Write to File
Function Write-OutputFile {
    Param ($Content)
    Add-Content -Path $OutputFile -Value $Content
}

# Clear Previous Report
if (Test-Path $OutputFile) { Remove-Item $OutputFile }

Write-OutputFile "Windows Enumeration & Weakness Report - $(Get-Date)"
Write-OutputFile "===========================================\n"

# System Information
Write-OutputFile "[+] System Information:"
$SystemInfo = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture
Write-OutputFile ($SystemInfo | Out-String)

# User Enumeration
Write-OutputFile "[+] Local User Accounts:"
$Users = Get-WmiObject Win32_UserAccount | Select-Object Name, SID, Disabled
Write-OutputFile ($Users | Out-String)

# Check for Administrators
Write-OutputFile "[+] Local Administrators:"
$Admins = Get-LocalGroupMember -Group "Administrators"
Write-OutputFile ($Admins | Out-String)

# Installed Applications
Write-OutputFile "[+] Installed Applications:"
$Apps = Get-WmiObject Win32_Product | Select-Object Name, Version
Write-OutputFile ($Apps | Out-String)

# Running Services
Write-OutputFile "[+] Running Services:"
$Services = Get-Service | Where-Object { $_.Status -eq 'Running' }
Write-OutputFile ($Services | Out-String)

# Network Configuration
Write-OutputFile "[+] Network Configuration:"
$NetConfig = Get-NetIPConfiguration | Select-Object InterfaceAlias, InterfaceIndex, IPv4Address, IPv6Address, DNSServer
Write-OutputFile ($NetConfig | Out-String)

# Open Ports
Write-OutputFile "[+] Open Network Ports:"
$OpenPorts = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalAddress, LocalPort, OwningProcess
Write-OutputFile ($OpenPorts | Out-String)

# Weak Password Policies
Write-OutputFile "[+] Password Policy:"
$PasswordPolicy = net accounts
Write-OutputFile ($PasswordPolicy | Out-String)

# Firewall Status
Write-OutputFile "[+] Firewall Status:"
$FirewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
Write-OutputFile ($FirewallStatus | Out-String)

# Antivirus Status
Write-OutputFile "[+] Antivirus Status:"
$AVStatus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select-Object displayName, productState
Write-OutputFile ($AVStatus | Out-String)

# Active Directory Enumeration (if applicable)
if ($env:USERDOMAIN -ne $env:COMPUTERNAME) {
    Write-OutputFile "[+] Active Directory Enumeration:"
    $DomainUsers = Get-ADUser -Filter * -Property DisplayName, Enabled | Select-Object DisplayName, Enabled
    Write-OutputFile ($DomainUsers | Out-String)
}

# Weak Encryption Detection (SMB, TLS, SSL, Hashing)
Write-OutputFile "[+] Checking for Weak Encryption Protocols:"
$SMBStatus = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol, EnableSMB2Protocol
Write-OutputFile ($SMBStatus | Out-String)

Write-OutputFile "[+] Windows Enumeration Completed!"
Write-OutputFile "Check $OutputFile for full report."
