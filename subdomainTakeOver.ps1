param(
[Parameter(Position=1)]
[string]$subDomainURLORTxtFilePath = ""
)

<#
    Description: 
        BugBounty tool. This script automate the finding of potential subdomain that could be tookover by looking for a potential alias vulnerability in the subdomain DNS.

    Entry(Not mendatory): 
        A specefic subdomain or a .TXT file with a list of subdomain.
      
    Output: 
        A list of all the potential vulnerable subdomain found. 
    Command exemple :  
        .\subdomainTakeOver.ps1
        .\subdomainTakeOver.ps1 .\subdomains.txt
        .\subdomainTakeOver.ps1 subdomain.exemple.com
    
#>


Write-Host "


####################################################################################################
 _____       _    ______                      _       
/  ___|     | |   |  _  \                    (_)      
\ `--. _   _| |__ | | | |___  _ __ ___   __ _ _ _ __  
 `--. \ | | | '_ \| | | / _ \| '_ ` _ \ / _` | | '_ \ 
/\__/ / |_| | |_) | |/ / (_) | | | | | | (_| | | | | |
\____/ \__,_|_.__/|___/ \___/|_| |_| |_|\__,_|_|_| |_|

 _____     _         _____              ___  
|_   _|   | |       |  _  |            |__ \ 
  | | __ _| | _____ | | | |_   _____ _ __ ) |
  | |/ _` | |/ / _ \| | | \ \ / / _ \ '__/ / 
  | | (_| |   <  __/\ \_/ /\ V /  __/ | |_|  
  \_/\__,_|_|\_\___| \___/  \_/ \___|_| (_)



______               ___  ___           _                __      
| ___ \        _     |  \/  |          | |              /  |     
| |_/ /_   _  (_)    | .  . |_ __      | | _____      __`| | ___ 
| ___ \ | | |        | |\/| | '__|     | |/ _ \ \ /\ / / | |/ __|
| |_/ / |_| |  _     | |  | | |     _  | |  __/\ V  V / _| |\__ \
\____/ \__, | (_)    \_|  |_/_|    (_) |_|\___| \_/\_/  \___/___/
        __/ |                                                    
       |___/
#####################################################################################################
"



$SubDomainsArray = @()
$DNSEntryArray = @()
$FilteredDomainArray = @()
$RecordsTypes = @("A","AAAA","NS","CNAME","CAA","MX","NS","PRT","SOA","SRV","TXT")
#$RecordsTypes = @("ALL")


if ($subDomainURLORTxtFilePath -eq "") {
    $subDomainURLORTxtFilePath = Read-Host -Prompt ' A specefic subdomain or a .TXT file with a list of subdomains: '
}


if ($subDomainURLORTxtFilePath.Substring($subDomainURLORTxtFilePath.Length-4) -eq ".txt") {
    $content = Get-content -Path $subDomainURLORTxtFilePath
    foreach ($subdomain in $content){
        $SubDomainsArray += $subdomain
    }
}else{
    $SubDomainsArray = @($subDomainURLORTxtFilePath)
}


foreach ($url in $SubDomainsArray){
    try
    {
        
        $Response = Invoke-WebRequest -Uri $url -ErrorAction Stop
        # This will only execute if the Invoke-WebRequest is successful.
        Write-Host "$($url) is reachable...Subdomain Dropped" -ForegroundColor Red
    }
    catch
    { 
        $FilteredDomainArray += $url
        Write-Host "$($url) is unreachable...Subdomain Added" -ForegroundColor Green
    }
}

Write-Host "[Looking For DNS records....]"-ForegroundColor Yellow
foreach ($element in $FilteredDomainArray) {
    $DNSEntryObject = @{}
    foreach($record in $RecordsTypes){
        
        try{
                $DNSEntryObject = Resolve-DnsName -Name $element -Type $record -erroraction silentlycontinue
                if ($DNSEntryObject.Type -eq "CNAME"){
                    Write-Host "$($element) : CNAME response received" -ForegroundColor Green
                    $DNSEntryArray += $DNSEntryObject
                }
            
            }catch{Continue}
    }
}
Write-Host "[Done.]
"-ForegroundColor Yellow

Write-Host "Potential Subdomain Takeover :" -ForegroundColor Cyan

if ($DNSEntryArray.Count -eq 0) {
    Write-Host "None where found..."
}
else {
    foreach ($element in $DNSEntryArray) {
        if ($element.Type -eq "CNAME"){
            Write-Host "URL: $($element.name)   CNAME : $($element.NameHost)"
        }
    }
}
