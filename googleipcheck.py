import requests
import re
import urllib3
from config import API_KEY

# Disable the warning 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


base_url = 'https://www.virustotal.com/api/v3/ip_addresses/'

file = open('ioc.txt', 'r')
x = file.readlines()

for ip in x:
    ip = ip.strip()  # 줄 끝의 공백 문자 개행 문자 제거
    url = f"{base_url}{ip}"

  
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

	# API 호출 부분
    response = requests.get(url, headers=headers, verify=False)
    response_text = response.text

	 

    def dellist(response_text, ip):
        patterns = [
            r'"as_owner": "ORACLE',
            r'"as_owner": "MICROSOFT',
            r'"as_owner": "GOOGLE',
            r'"as_owner": "AMAZON'
        ]
        for pattern in patterns:
            if re.search(pattern, response_text, re.IGNORECASE): 
                owner = pattern
                print("IP:", ip, owner)

    dellist(response_text, ip)