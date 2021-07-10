import requests
import argparse
import re
import os
import dns.resolver


RED = "\033[91m"
GREEN = "\033[92m"
BLUE = "\033[94m"
WHITE = "\033[0;37m"


class PSudomainTO: 
    def __init__(self, domain, cname): 
        self.domain = domain 
        self.cname = cname

class util: 

    def formating(domainList):
        if os.path.isfile(domainList):
            readWords = open(domainList, 'r')

        else:
            exit("{}File Not Found...".format(RED))	
        
        print("{}[+] Loading Targets.... [+]\033[94m\n".format(WHITE))			
        subdomainlist = []
    
        for words in readWords:
            if not words.isspace():
                words = words.rstrip()
                words = words.replace("https://", "")
                words = words.replace("http://", "")
                words = words.replace("https://www.", "")
                words = words.replace("http://www.", "")
                words = words.replace("/", "")
                words = "http://{}".format(words)
                subdomainlist.append(words)
            
    
        readWords.close()

        return subdomainlist


    def deformating(domainlist): 
        deformatedsubdomain = []
        
        for domain in domainlist: 
            domain = domain.replace("http://","")
            deformatedsubdomain.append(domain)

        return deformatedsubdomain



if __name__ == "__main__": 

    print("""

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

                    By Mr.Lew1s

    """)



    parser = argparse.ArgumentParser(description="Subdomain Takeover")
    parser.add_argument('-l','--list',default='',help='python3 subdomainTakeOver.py [-l, --list] file contain list of domains')
    args = parser.parse_args()
    domainList = args.list

    if len(str(domainList)) > 0:

        potentialvulnerablesubdomain = []
        potentialVulnerableSubdomainWithCNAMEDnsRecord = []

        subList = util.formating(domainList)

        if len(subList) > 0:
            print(WHITE,"\n[!] Total {} subdomain(s) as been Loaded [!]\033[94m".format(len(subList)))

            print("{}[!] Looking For Subdomain Takeover..... [!]\n\033[94m".format(WHITE))
            
            for domain in subList:
                print("{}[-] Testing {} [-]\033[94m".format(WHITE, domain))		
                
                try:
                    subDoamin = requests.get("{}".format(domain.rstrip()), timeout=5).text
                    print("{}  -- Not Vulnerable {}\033[94m \n".format(BLUE, domain))
                        
                except:
                        potentialvulnerablesubdomain.append(domain)
                        print("{}  -- Domain is unreachable...Added to potential subdomain takeover\033[94m \n".format(BLUE))			
            
            
            if len(potentialvulnerablesubdomain) > 0:
                print("{}[!] Checking DNS Records of {} potential vulnerable subdomain(s)... [!]\n\033[94m".format(WHITE, len(potentialvulnerablesubdomain)))
                
                potentialvulnerablesubdomain = util.deformating(potentialvulnerablesubdomain)
                
                for domain in potentialvulnerablesubdomain:
                    try: 
                        print("{}[-] Looking DNS Record for {} [-]\033[94m".format(WHITE, domain))

                        dnsrecord = dns.resolver.resolve(domain, 'CNAME')
                        
                        for data in dnsrecord:

                            print("{}  -- DNS Record Found : {} \n".format(GREEN, data, domain))
                            potentialVulnerableSubdomainWithCNAMEDnsRecord.append(PSudomainTO(domain,data)) 
                    
                    except:
                        print("{}  -- No DNS Record Found \033[94m \n".format(BLUE, domain))
                        
                    
                if len(potentialVulnerableSubdomainWithCNAMEDnsRecord) > 0: 
                    takeover = open('takeover.txt','a')
                    print("{}Potential subdomain that could be took over : \033[94m \n".format(WHITE))
                    for obj in potentialVulnerableSubdomainWithCNAMEDnsRecord: 
                        print ("{}Domain : {}  CNAME : {} \n".format(GREEN,obj.domain,obj.cname))
                        takeover.write("{}Domain : {}  CNAME : {} \n".format(GREEN,obj.domain,obj.cname))
                    takeover.close()
                else: 
                    print("{}[-] No DNS Record was Found in the list of potential vulnerable Subdomain [-]\033[94m".format(RED))
            
            
            else: 
                print(RED,"\n[!] No potential vunerable subdomain was found from the {} subdomain(s) targeted [!]\033[94m".format(len(subList)))

    else:
        print("Author: Mr.Lew1s\nArguments:\n\t--help, -h: Show Help\n\t--list, -l: file contain list of domains\n") 
