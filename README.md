# Subdomain Takeover Finder

## Subdomain Takeover? 

Subdomain Takeover? is a BugBounty tool / Pentesting Tool. This script automate the finding of potential subdomain that could be tookover by looking for alias vulnerability in the subdomain DNS. The script is available in **python3** or **Powershell** is a script available in powershell or python 

### **Python Version** 

#### **Usage :**
    
    python3 subdomainTakeOver.py -l targets

    subdomainTakeOver.py => script name
    -l                   => for list 
    file.txt             => file that contain subdomain

#### **Help :**
    python3 subdomainTakeOver.py -h

### **Powershell Version** 


#### **Usage :**

    .\subdomainTakeOver.ps1 .\subdomains.txt

    .\subdomainTakeOver.ps1 subdomain.exemple.com

#### **Parameter :**
A specefic subdomain or a .TXT file with a list of subdomain.
 
#### **Output :**
A list of all the potential vulnerable subdomain found. 
