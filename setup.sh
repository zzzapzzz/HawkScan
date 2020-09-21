#!/bin/bash
os=$(uname)
v_python=$(python --version)
pip2_dry=$(sudo pip install requests pyopenssl pprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets dryscrape)
pip2_ndry=$(sudo pip install requests pyopenssl pprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets)
pip3_dry=$(sudo pip3 install requests pyopenssl pprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets dryscrape)
pip3_ndry=$(sudo pip3 install requests pyopenssl pprint queuelib fake_useragent python-whois argparse bs4 dnspython wafw00f python-whois sockets)
if [[ $os = "*Linux*" ]] && [[ $v_python != "*3*" ]];
then
	$pip2_dry #install pip python2 with dryscraper
elif [[ $os = "*Linux*" ]] && [[ $v_python == "*3*" ]]
	$pip3_dry #install pip python3 with dryscraper
elif [[ $os != "*Linux*" ]] && [[ $v_python != "*3*" ]]
	$pip2_ndry #install pip python2 without dryscraper
elif [[ $os != "*Linux*" ]] && [[ $v_python == "*3*" ]]
	$pip3_ndry #install pip python3 without dryscraper
fi