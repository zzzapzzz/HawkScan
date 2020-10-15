#! /usr/bin/env python
# -*- coding: utf-8 -*-

try: 
    from googlesearch import search 
except ImportError:  
    print("No module named 'google' found")
import sys
import requests
from config import PLUS, WARNING, INFO, LINE, LESS
import time

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def timer(length):
    #timer to wait
    start = time.time()
    running = True
    while running:
        if time.time() - start >= length:
            running = False
        else:
            sys.stdout.write(""+ str(length - (time.time() - start)) + " secondes...\r")
            sys.stdout.flush()
    print("\n")
  

def query_dork(domain):
    """
    query_dork: function to search google dork
    """
    key_break = False
    found = False
    answer_yes = False
    print(INFO + "GOOGLE DORK")
    print(LINE)
    if 'www' in domain:
        direct = domain.split('.')
        director = direct[1]
        domain = "{}.{}".format(direct[1], direct[2].replace("/",""))
    else:
        direct = domain.split('/')
        director = direct[2]
        domain = director
    ext = domain.split(".")[1]
    bill = 'facture site:{} filetype:pdf'.format(domain) if "fr" in ext else 'bill site:{} filetype:pdf'.format(domain) #FR/EN
    #Didn't hesitate to add your queries
    query = [
    bill,
    'budget site:{} filetype:pdf'.format(domain),
    'site:{} ext:action OR ext:adr OR ext:ascx OR ext:asmx OR ext:axd OR ext:backup OR ext:bak OR ext:bkf OR ext:bkp OR ext:bok OR ext:achee OR ext:cfg OR ext:cfm OR ext:cgi OR ext:cnf OR ext:conf OR ext:config OR ext:crt OR ext:csr OR ext:csv OR ext:dat OR ext:doc OR ext:docx OR ext:eml OR ext:env OR ext:exe OR ext:gz OR ext:ica OR ext:inf OR ext:ini OR ext:java'.format(domain),
    'site:{} ext:json OR ext:key OR ext:log OR ext:lst OR ext:mai OR ext:mbox OR ext:mbx OR ext:md OR ext:mdb OR ext:nsf OR ext:old OR ext:oraext: OR ext:pac OR ext:passwd OR ext:pcf OR ext:pem OR ext:pgp OR ext:pl OR ext:plist OR ext:pwd OR ext:rdp OR ext:reg OR ext:rtf OR ext:skr OR ext:sql OR ext:swf OR ext:tpl'.format(domain),
    'site:{} ext:txt OR ext:url OR ext:wml OR ext:xls OR ext:xlsx OR ext:xml OR ext:xsd OR ext:yml OR ext:NEW OR ext:save'.format(domain),
    'site:{} intitle:"index of"'.format(domain),
    'site:{} intitle:"index of" .env'.format(domain)
    ]
    for s in query:
        try:
            for j in search(s, tld="com", num=30, stop=100, pause=2.5):
                req = requests.get(j, verify=False) 
                if req.status_code == 200:
                    found = True
                    print("{}{}".format(PLUS, j))
        except Exception as e:
            if "429" in str(e):
                print("{}[429] Google blocked us, please wait 1 minute...".format(LESS))
                if not answer_yes: 
                    try:
                        oq = raw_input("{}Do you want try the other queries? (y:n)".format(INFO))
                    except:
                        oq = input("{}Do you want try the other queries? (y:n)".format(INFO))
                    if oq == "y" or oq == "Y":
                        answer_yes = True
                        timer(60)
                    else:
                        key_break = True
                        break
                else:
                    timer(60)
        if key_break == True:
            break
    if not found:
        print("{}Nothing links found".format(LESS))
    print(LINE)

"""if __name__ == '__main__':
    domain = "https://www..fr/" #DEBUG
    query_dork(domain)"""