Changelog:
----------

	- 1.3.3
		Adding new function which try automatically if it's possible scanning with "localhost" host

	- 1.3.2
		Adding Dockerfile
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