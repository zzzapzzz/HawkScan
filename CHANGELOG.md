Changelog:
----------
	- 1.5.5
		Add google dork requests

	- 1.5.4
		Add option "--js" for scan and analyse JS
		Delete "dryscrape" librarie for the moment, many error with it, I'll remake it later

	- 1.5.3
		Add setup.py

	- 1.5.2
		Try differents bypass for 403 code error
		Update dico.txt

	- 1.5.1
		New banner
		Fix bugs

	- 1.5
		Auto activate JS during scan if the webite is full JS (website 2.0)

	- 1.4
		Adding Dockerfile

	- 1.3.3
		Adding new function which try automatically if it's possible scanning with "localhost" host

	- 1.3.2
		Replace "--cookie" by "-H" for different header values; ex: -H "Host:test" // -H "Authentification:cookie" (not space after ":" or "=")

	- 1.3.1:
		Code review
		New logo
		Adding Changelog

	- 1.2:
		Adding news words in dico.txt (old dico_extra.txt)
		Adding extensions in backup check test function, option -b (.json, .xml, .bkp...) => very long
		Test bypass of waf rate limited in real time (X-Originating-IP...)
		Exclude response http code (--exclude 403)
		Filter on response http code in report

	- 1.0:
	  	Better management Threads
		Add news words in dico_extra.txt
		New style for the report
		Errors log management