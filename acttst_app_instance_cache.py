import json
import xml.etree.ElementTree as ET
import logging
import time
import datetime
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

response = {}

# For app instance cache, use the 'connect_app_instance_cache' to be the response key.
        # The value needs to be a string. It can be a json string containing different fields or any other format,
        # depending on how you want to use it in scripts.
response['connect_app_instance_cache'] = json.dumps({'test': 'test'})
# response["connect_app_instance_cache"]
# response["error"] = 
# if connect_app_instance_cache is in the response object, it will overwrite previous cache value.
# Otherwise, the previous cache value will remain the same.