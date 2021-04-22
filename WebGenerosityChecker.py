import requests
import json
import time
from bs4 import BeautifulSoup

# url_scan = "https://pattxrn0913.shortcm.li/nFb0Jg"
# url_scan = "https://www.charusat.ac.in"
# url_scan = "https://www.csm-testcenter.org/download/malicious/index.html"
api_key = "7371980d0b47237db8eb070b79c0a196acc50afbd22617e7c711047187af135d"

def UrlScanning(url_scan):
  url_api="https://www.virustotal.com/vtapi/v2/url/report"
  
  params = {'apikey':api_key, 'resource': url_scan}
  response = requests.get(url_api,params=params)
  response_json = json.loads(response.content)
  reportBy=[]

  for i in response_json['scans']: 
    if(str(response_json['scans'][i]['detected'])=="True"):
      reportBy.append(i)
  scanId = response_json['scan_id']
  scanDate = response_json['scan_date']

  if response_json['positives'] <= 0:
    with open('results.txt','a') as vt:
      vt.write('\nScan Id = ') and vt.write(scanId) and vt.write('\nScan Date = ') and vt.write(scanDate)
      vt.write('\nSite Url = ') and vt.write(url_scan) and vt.write(' is Not Malicious.\n')
  elif response_json['positives'] >= 1 and response_json['positives'] <= 3:
    with open('results.txt','a') as vt:
      vt.write('\nScan Id = ') and vt.write(scanId) and vt.write('\nScan Date = ') and vt.write(scanDate)
      vt.write('\nSite Url = ') and vt.write(url_scan) and vt.write(' May be Malicious.\nReported by : ')
      for listitems in reportBy:
        vt.write(listitems) and vt.write('    ')
      vt.write('\n')
  elif response_json['positives'] >= 4:
    with open('results.txt','a') as vt:
      vt.write('\nScan Id = ') and vt.write(scanId) and vt.write('\nScan Date = ') and vt.write(scanDate)
      vt.write('\nSite Url = ') and vt.write(url_scan) and vt.write(' is Malicious.\nReported by : ')
      for listitems in reportBy:
        vt.write(listitems) and vt.write('    ')
      vt.write('\n')
  else:
    print('\nUrl Not Found\n')

def IPScanning(ip_scan):
  response = requests.get("https://www.virustotal.com/api/v3/ip_addresses/%s" %ip_scan, headers={'User-agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:61.0) Gecko/20100101 Firefox/61.0', 'x-apikey': '%s' %api_key}).json()
  dict_web = response["data"]["attributes"]["last_analysis_results"]
  result_report = []
  reportBy = []
  tot_detect = 0
  for i in dict_web:
    if dict_web[i]["category"] == "malicious" or dict_web[i]["category"] == "suspicious":
      result_report.append(dict_web[i]["result"])
      reportBy.append(dict_web[i]["engine_name"])
      tot_detect = 1 + tot_detect
  res=[]
  for i in result_report:
    if i not in res:
      res.append(i)
  result_report=res

  if tot_detect > 0:
    with open('results.txt','a') as vt:
      vt.write("\nIP Address = ") and vt.write(ip_scan) and vt.write(" is Malicious.\nReported by : ")
      for listitems in reportBy:
        vt.write(listitems) and vt.write('    ')
      vt.write('\n')
  else:
    with open('results.txt','a') as vt:
      vt.write("\nIP Address = ") and vt.write(ip_scan) and vt.write(" is not Malicious.\n")


print('\n**************Web Generosity Checker**************\n')


while True:
  print('1) Url Scanning.')
  print('2) IP Address Scanning.')
  print('3) Exit.\n')

  choice = int(input('Enter from above choice : '))
  if choice == 1:
    print('\n**************Url Scanning**************\n')
    url_scan=input('Enter url you want to scan : ')
    UrlScanning(url_scan)
  elif choice == 2:
    print('\n**************IP Address Scanning**************\n')
    ip_scan=input('Enter IP Address you want to scan : ')
    IPScanning(ip_scan)
  elif choice == 3:
    print('\nEnd of Program.\n')
    exit(0)
  else:
    print('\nYour choice is not proper.\n')