# HawkScan

![alt tag](https://github.com/c0dejump/HawkScan/blob/master/static/logo.jpg)

Security Tool for Reconnaissance and Information Gathering on a website. (python 2.x & 3.x)

This script use "WafW00f" to detect the WAF in the first step (https://github.com/EnableSecurity/wafw00f)

This script use "Sublist3r" to scan subdomains (https://github.com/aboul3la/Sublist3r)

This script use "waybacktool" to check in waybackmachine (https://github.com/Rhynorater/waybacktool)

# News
**!** Version 1.5.2      
**!** Try differents bypass for 403 code error      
**!** Update dico.txt         

# Features
 - [x] URL fuzzing and dir/file detection
 - [x] Test backup/old file on all the files found (index.php.bak, index.php~ ...)
 - [x] Check header information
 - [x] Check DNS information
 - [x] Check whois information
 - [x] User-agent random or personal
 - [x] Extract files
 - [x] Keep a trace of the scan
 - [x] Check @mail in the website and check if @mails leaked
 - [x] CMS detection + version and vulns
 - [x] Subdomain Checker
 - [x] Backup system (if the script stopped, it take again in same place)
 - [x] WAF detection
 - [x] Add personal prefix
 - [x] Auto update script
 - [x] Auto or personal output of scan (scan.txt)
 - [x] Check Github
 - [x] Recursif dir/file
 - [x] Scan with an authenfication cookie
 - [x] Option --profil to pass profil page during the scan
 - [x] HTML report
 - [x] Work it with py2 and py3
 - [x] Add option rate-limit if app is unstable (--timesleep)
 - [x] Check in waybackmachine
 - [x] Response error to WAF
 - [x] Check if DataBase firebaseio existe and accessible
 - [x] Automatic threads depending response to website (and reconfig if WAF detected too many times). Max: 30
 - [x] Search S3 buckets in source code page
 - [x] Testing bypass of waf if detected
 - [x] Testing if it's possible scanning with "localhost" host
 - [x] Dockerfile
 - [x] Active JavaScript on website 2.0 (full js)
 - [x] Try differents bypass for 403 code error
 
# TODO 
**P1 is the most important**

 - [ ] JS parsing and analysis [P1]
 - [ ] Analyse html code webpage [P1]
 - [ ] On-the-fly writing report [P1]
 - [ ] Check HTTP headers/ssl security [P2]
 - [ ] Fuzzing amazonaws S3 Buckets [P2]
 - [ ] Anonymous routing through some proxy (http/s proxy list) [P2]
 - [ ] Check pastebin [P2]
 - [ ] Access token [P2]
 - [ ] Check source code and verify leak or sentsitive data in the Github [P2]
 - [ ] Check phpmyadmin version [P3]
 - [ ] Scan API endpoints/informations leaks [ASAP]
 
 # Usage
 > 
 
       pip(3) install -r requirements.txt 
    If problem with pip3:    
       sudo python3 -m pip install -r requirements.txt

    If you have problem to install the library "dryscrape" you can follow this link:
       https://www.it-swarm.dev/fr/python/pip-install-dryscrape-echoue-avec-error-errno-2-ce-fichier-ou-repertoire-srcwebkit-server/827034588/
 > 
  
 >
     
    usage: hawkscan.py [-h] [-u URL] [-w WORDLIST] [-s SUBDOMAINS] [-t THREAD] [-a USER_AGENT] [--redirect] [-r] [-p PREFIX] [-o OUTPUT] [--cookie COOKIE_] [--exclude EXCLUDE] [--timesleep TS] [--auto]
 
 > 
 
    optional arguments: 
     -h, --help         show this help message and exit
     -u URL             URL to scan [required]
     -w WORDLIST        Wordlist used for URL Fuzzing. Default: dico.txt
     -s SUBDOMAINS      Subdomain tester
     -t THREAD          Number of threads to use for URL Fuzzing. Default: 20
     -a USER_AGENT      Choice user-agent 
     --redirect         For scan with redirect response (301/302) 
     -r                 Recursive dir/files      
     -p PREFIX          Add prefix in wordlist to scan      
     -o OUTPUT          Output to site_scan.txt (default in website directory)       
     -b                 Add a backup file scan like 'exemple.com/~exemple/, exemple.com/ex.php.bak...' but longer             
     -H HEADER_         modify HEADER              
     --exclude EXCLUDE  To define a page or response code status type to exclude during scan                                            
     --timesleep TS     To define a timesleep/rate-limit if app is unstable during scan                                 
     --auto             Automatic threads depending response to website. Max: 30      
     --update           For automatic update

 >

# Exemples

 >
    //Basic
    python hawkscan.py -u https://www.exemple.com/

    //With specific dico
    python hawkscan.py -u https://www.exemple.com/ -w dico_extra.txt

    //with 30 threads
    python hawkscan.py -u https://www.exemple.com/ -t 30

    //With backup files scan
    python hawkscan.py -u https://www.exemple.com/ -b

    //With an exclude page
    python hawkscan.py -u https://www.exemple.com/ --exclude https://www.exemple.com/profile.php?id=1

    //With an exclude response code
     python hawkscan.py -u https://www.exemple.com/ --exclude 403

 >

# Thanks
Layno (https://github.com/Clayno/)      
Sanguinarius (https://twitter.com/sanguinarius_Bt)        
Cyber_Ph4ntoM (https://twitter.com/__PH4NTOM__ )  

# Paypal

https://www.paypal.me/c0dejump

