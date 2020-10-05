import sys, os, platform

os_type = "{}".format(platform.system())
v_python = "{}".format(sys.version)

if "Linux" in os_type and "2." in v_python:
	#install pip python2 with dryscraper
	os.system("sudo pip install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets dryscrape")
elif "Linux" in os_type and "3." in v_python:
	#install pip python3 with dryscraper
	os.system("sudo pip3 install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets dryscrape")
elif "Linux" not in os_type and "2." in v_python:
	#install pip python2 without dryscraper
	os.system("sudo pip install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets")
elif "Linux" not in os_type and "3." in v_python:
	#install pip python3 without dryscraper
	os.system("sudo pip3 install requests pyopenssl prettyprinter prettyprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets")
else:
	print("OS not recon, please install it manualy with requirements.txt")