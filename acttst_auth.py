import json
import logging
import time
import datetime
import xml.etree.ElementTree as ET
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# <--! being test params area !-->
params = {
    'connect_acttst_url': '10.210.20.21',
    'connect_acttst_username': 'localaccount',
    'connect_acttst_password': 'localaccount',
    'connect_authorization': '3600'
}
# <--! end test params area !-->

response = {}
ip_host = str(params.get('connect_acttst_url')).strip()
user = str(params.get('connect_acttst_username')).strip()
password = str(params.get('connect_acttst_password')).strip()
r = requests.post(url='https://{}/connect/v1/authentication/token'.format(ip_host), headers={'Content-Type': 'application/json'}, data=json.dumps({'username': user, 'password': password, 'app_name': 'acttst', 'expiration': str(params.get('connect_authorization').strip())}), verify=False)
if r.status_code == 200:
    resp_dict = r.json()
    if resp_dict.get('data').get('token'):
        response['succeeded'] = True
        response['token'] = resp_dict.get('data').get('token')
else:
    response['succeeded'] = False
    response['error'] = 'Status Code: {}\nContent: {}'.format(r.status_code, r.content)
# print(response)
# for script/auth failure:
# response['error'] = oh no!
