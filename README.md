# Potential Subdomain Takeover Script
BugBounty tool. This script automate the finding of potential subdomain that could be tookover by looking for alias vulnerability in the subdomain DNS.

## Parameter
A specefic subdomain or a .TXT file with a list of subdomain.
 
## Output
A list of all the potential vulnerable subdomain found. 

## Command Exemple

.\subdomainTakeOver.ps1 .\subdomains.txt
.\subdomainTakeOver.ps1 subdomain.exemple.com
