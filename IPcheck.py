import requests
import re
import urllib3
from config import API_KEY

# Disable the warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# 바이러스토탈 API 키와 기본 URL 설정
base_url = "https://www.virustotal.com/api/v3/ip_addresses/"

file = open("ioc.txt", "r")
x = file.readlines()  # 파일 내용을 줄 단위로 읽기

for ip in x:
    ip = ip.strip()  # 줄 끝의 공백 문자나 개행 문자 제거
    url = f"{base_url}{ip}"  # URL 생성
    
    # 요청 파라미터 설정
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    # API 호출
    response = requests.get(url, headers=headers, verify=False)
    
    # 패턴을 찾아서 malicious 수치 추출
    pattern_1 = r'"malicious":\s*\d+'
    matches_1 = re.findall(pattern_1, response.text)
    
    pattern_2 = r'"country": "[A-Z]{2}"'  # 국가 코드 패턴 (2자리 대문자)
    matches_2 = re.findall(pattern_2, response.text)
    
    for match in matches_1:
        number = int(re.search(r'\d+', match).group())  # malicious 숫자 추출
        for match2 in matches_2:
            if number > 5:
                print("IP:", ip," malicious:", number," ",match2,sep="")    
