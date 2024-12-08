import requests
import re
import urllib3
from config import API_KEY

# Disable the warning 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

 # 바이러스토탈 API 키와 기본 URL 설정 
base_url = 'https://www.virustotal.com/api/v3/ip_addresses/'

file = open('ioc.txt', 'r')
x = file.readlines() #파일 내용을 줄 단위로 읽어율니다

for ip in x:
    ip = ip.strip()  # 줄 끝의 공백 문자나 개행 문자 제거
    url = f"{base_url}{ip}"

    # 요청 파라미터 설정
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }

	# API 호출 
    response = requests.get(url, headers=headers, verify=False)
    response_text = response.text

	 
	 # 특정 소유자 제외 
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

    #소유자 필터링 함수
    dellist(response_text, ip)