import json
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


response = {}
response['succeeded'] = True
response['result_msg'] = 'Well done ;)'