import json
import datetime
import time
import logging
import xml.etree.ElementTree as ET
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# <--! begin logging configuration dev area !-->
logging.basicConfig(
    level=logging.DEBUG,
    filename='acttst_action_1.log',
    filemode='w',
    format='%(asctime)s - %(levelname)s - %(message)s'
)
# <--! end logging configuration dev area !-->


# <--! begin testing params area !-->
# params = {'comp_application': '[{"app_name":"operationalaccreditation.dod.mil:Global:_DISA:D:DODNET-U-DS ID 28015:;0000113221","app_version":"2020-09-16 20:20:28.280","app_user":"All Users"},{"app_name":"ownorg.dod.mil:Global:Gov:_United States:DOD:DISA:;0000000014","app_version":"2020-09-16 20:20:28.280","app_user":"All Users"},{"app_name":"Google Chrome","app_version":"114.0.5735.199","app_user":"All Users"},{"app_name":"Microsoft Edge WebView2 Runtime","app_version":"114.0.1823.67","app_user":"All Users"},{"app_name":"Microsoft OneDrive","app_version":"23.127.0618.0001","app_user":"POD10\\\\upstartlab"},{"app_name":"Microsoft Update Health Tools","app_version":"3.70.0.0","app_user":"All Users"},{"app_name":"Microsoft Visual C++ 2019 X64 Additional Runtime - ","app_version":"14.28.29914","app_user":"All Users"},{"app_name":"geolocation.DoD.mil:Global:UNITE:MLD:FTGRGGMD:DISA HQS Complex:;0000037780","app_version":"2021-01-12 00:06:57.342","app_user":"All Users"},{"app_name":"Microsoft Visual C++ 2019 X86 Minimum Runtime - ","app_version":"14.28.29914","app_user":"All Users"},{"app_name":"Microsoft OneDrive","app_version":"21.220.1024.0005","app_user":"POD10\\\\jwilson"},{"app_name":"adminorg.dod.mil:Global:Gov:_United States:_DOD:DISA:OC:SE:SE6:;0000068495","app_version":"2020-09-16 20:20:28.280","app_user":"All Users"},{"app_name":"Microsoft Edge","app_version":"114.0.1823.79","app_user":"All Users"},{"app_name":"Microsoft Visual C++ 2019 X64 Minimum Runtime - ","app_version":"14.28.29914","app_user":"All Users"},{"app_name":"Microsoft Visual C++ 2015-2019 Redistributable (x86) - 14.28.29914","app_version":"14.28.29914.0","app_user":"All Users"},{"app_name":"ccsafa.dod.mil:Global:DISA:;0000000014","app_version":"2020-09-16 12:20:24.231","app_user":"All Users"},{"app_name":"Microsoft Visual C++ 2015-2019 Redistributable (x64) - 14.28.29914","app_version":"14.28.29914.0","app_user":"All Users"},{"app_name":"cndsp.dod.mil:Global:Gov:USCYBERCOM:DISA CSSP:;0000000014","app_version":"2020-09-16 20:20:28.280","app_user":"All Users"},{"app_name":"Microsoft Visual C++ 2019 X86 Additional Runtime - ","app_version":"14.28.29914","app_user":"All Users"},{"app_name":"Microsoft Edge Update","app_version":"1.3.177.11","app_user":"All Users"},{"app_name":"Configuration Manager Client","app_version":"5.00.9102.1000","app_user":"All Users"},{"app_name":"cocomaor.dod.mil:Global:USNORTHCOM:;0000036996","app_version":"2020-05-13 18:58:39.347","app_user":"All Users"},{"app_name":"Google Update Helper","app_version":"1.3.35.441","app_user":"All Users"},{"app_name":"ScreenConnect Client (9bbe344b6478184d)","app_version":"21.15.5652.7992","app_user":"All Users"},{"app_name":"Microsoft Policy Platform","app_version":"68.1.9086.1017","app_user":"All Users"},{"app_name":"ConnectWise Automate Remote Agent","app_version":"22.0.440","app_user":"All Users"}]', 'service_installed': '["Windows Event Log","Server","Microsoft Store Install Service","Distributed Transaction Coordinator","COM+ System Application","Storage Tiers Management","Device Association Service","Device Setup Manager","Google Update Service (gupdate)","Update Orchestrator Service","Smart Card Removal Policy","DHCP Client","Spot Verifier","Offline Files","Hyper-V Heartbeat Service","Data Sharing Service","Delivery Optimization","Windows Defender Firewall","Device Install Service","Local Session Manager","Device Management Wireless Application Protocol (WAP) Push message Routing Service","SSDP Discovery","Cryptographic Services","Background Intelligent Transfer Service","Link-Layer Topology Discovery Mapper","Task Scheduler","Certificate Propagation","Wired AutoConfig","COM+ Event System","Windows Connection Manager","Windows Management Instrumentation","Microsoft (R) Diagnostics Hub Standard Collector Service","Windows Event Collector","Windows Licensing Monitoring Service","Connected Devices Platform Service","Hyper-V Volume Shadow Copy Requestor","Windows Error Reporting Service","Net.Tcp Port Sharing Service","Remote Desktop Configuration","Windows Remote Management (WS-Management)","Windows Update Medic Service","State Repository Service","User Access Logging Service","Shell Hardware Detection","Microsoft Passport Container","ForeScout Remote Inspection Service","Secondary Logon","Optimize drives","Power","Plug and Play","Portable Device Enumerator Service","Group Policy Client","Remote Procedure Call (RPC)","Windows Update","Time Broker","System Event Notification Service","AVCTP service","WalletService","Remote Procedure Call (RPC) Locator","System Events Broker","SNMP Trap","Network Setup Service","Windows Audio Endpoint Builder","Routing and Remote Access","DevQuery Background Discovery Broker","Downloaded Maps Manager","Performance Logs & Alerts","ScreenConnect Client (9bbe344b6478184d)","Resultant Set of Policy Provider","Themes","Problem Reports and Solutions Control Panel Support","Remote Registry","Storage Service","CNG Key Isolation","CoreMessaging","Security Accounts Manager","Hyper-V Guest Service Interface","Windows Modules Installer","Bluetooth Audio Gateway Service","Splunkd Service","User Experience Virtualization Service","User Profile Service","Encrypting File System (EFS)","Network List Service","Device Management Enrollment Service","Windows PushToInstall Service","Still Image Acquisition Events","Smart Card Device Enumeration Service","Microsoft iSCSI Initiator Service","Bluetooth Support Service","Quality Windows Audio Video Experience","Hyper-V Guest Shutdown Service","Geolocation Service","Smart Card","Microsoft App-V Client","Workstation","Radio Management Service","Network Connectivity Assistant","Background Tasks Infrastructure Service","Touch Keyboard and Handwriting Panel Service","Diagnostic Service Host","ConnectWise Automate Watchdog Service","Windows Defender Antivirus Network Inspection Service","Google Chrome Elevation Service (GoogleChromeElevationService)","Secure Socket Tunneling Protocol Service","AllJoyn Router Service","User Manager","Windows License Manager Service","KDC Proxy Server service (KPS)","Windows Security Service","Special Administration Console Helper","Diagnostic Policy Service","Windows Installer","Windows Image Acquisition (WIA)","KtmRm for Distributed Transaction Coordinator","Auto Time Zone Updater","Program Compatibility Assistant Service","Windows Audio","App Readiness","WMI Performance Adapter","Network Connection Broker","AppX Deployment Service (AppXSVC)","Software Protection","System Guard Runtime Monitor Broker","Windows Media Player Network Sharing Service","Microsoft Passport","ConnectWise Automate Monitoring Service","WinHTTP Web Proxy Auto-Discovery Service","Netlogon","Hyper-V Time Synchronization Service","Application Management","Virtual Disk","HV Host Service","UPnP Device Host","Remote Access Auto Connection Manager","Connected User Experiences and Telemetry","Application Information","Windows Defender Advanced Threat Protection Service","Printer Extensions and Notifications","Windows Mobile Hotspot Service","Windows Insider Service","Windows Defender Antivirus Service","Hyper-V PowerShell Direct Service","Google Update Service (gupdatem)","Windows Font Cache Service","OpenSSH Authentication Agent","Network Connections","RPC Endpoint Mapper","Capability Access Manager Service","DNS Client","Diagnostic System Host","Network Location Awareness","Sensor Data Service","Windows Push Notifications System Service","WarpJITSvc","Hyper-V Remote Desktop Virtualization Service","Windows Encryption Provider Host Service","Remote Desktop Services","Performance Counter DLL Host","Microsoft Account Sign-in Assistant","Windows Search","Sensor Monitoring Service","SysMain","Enterprise App Management Service","Payments and NFC\\/SE Manager","Human Interface Device Service","Web Account Manager","IP Helper","Application Layer Gateway Service","Phone Service","Windows Camera Frame Server","Hyper-V Data Exchange Service","Function Discovery Provider Host","IPsec Policy Agent","Network Store Interface Service","Microsoft Software Shadow Copy Provider","Extensible Authentication Protocol","Windows Time","Remote Access Connection Manager","ActiveX Installer (AxInstSV)","Windows Biometric Service","Sensor Service","Internet Connection Sharing (ICS)","Application Identity","Telephony","Client License Service (ClipSVC)","Function Discovery Resource Publication","TCP\\/IP NetBIOS Helper","GraphicsPerfSvc","Microsoft Storage Spaces SMP","Credential Manager","Print Spooler","IKE and AuthIP IPsec Keying Modules","Embedded Mode","Volume Shadow Copy","Shared PC Account Manager","Remote Desktop Services UserMode Port Redirector","DCOM Server Process Launcher","Distributed Link Tracking Client","Base Filtering Engine"]', 'acttst_action_1_boolean_param': 'true', 'ssh_linux_manage': 'false', 'linux_manage': 'false', 'av_install': '["windows_defender"]', 'openports': '["135\\/TCP","57277\\/TCP","445\\/TCP"]', 'mac_vendor_string': 'VMWARE, INC.', 'hostname': 'POD10-SPLUNK-01.pod10.lab.upstartcyber.com', 'guest_corporate_state': 'CORPORATE', 'hwi_disk': '[{"drive_type":"5","file_system":"UDF","size":"5051.33984375","device_id":"D:","media_type":"11","name":"D:","volume_name":"SSS_X64FREE_EN-US_DV9","description":"CD-ROM Disc","availability":null,"free_space":"0.0","status":null},{"drive_type":"3","file_system":"NTFS","size":"204183.99609375","device_id":"C:","media_type":"12","name":"C:","volume_name":null,"description":"Local Fixed Disk","availability":null,"free_space":"178736.26171875","status":"OK"}]', 'cl_type': 'Managed', 'connect_app_device_parent': 'connect_acttst', 'arp_list': '["7309594939418667319;10.210.254.2;10.210.20.163;000c2945476c"]', 'connect_focal_appliance': '0', 'wmi_port': '135:1689189197', 'va_os_comp': '{"internal_version_number":"1809","flavor":null,"parent":"Windows Server 2019 64-bit","os_build_number":"17763.737","sp":null,"architecture":"64-bit"}', 'ip': '10.210.20.163', 'active': '1689211726', 'acttst_action_1_string_multi_param': 'Put what you want here ;) x2', 'connect_acttst_url': 'N/A', 'adm': '["online_again"]', 'connect_authorization': '60', 'acttst_action_1_int_param': '0', 'acttst_action_1_string_param': 'Put what you want here ;)', 'connect_api_rate_limit': '10', 'model_classification': 'Virtual Machine', 'connect_cert_validation': 'false', 'connect_acttst_username': '', 'os_classification': 'Windows', 'connect_c2c_focal_appliance': '0', '_timeinfo': '{"connect_c2c_focal_appliance":"1689109081","os_classification":"1689189197","windows_updates_waiting_for_reboot":"1689189101","ssh_linux_manage":"1689211814","linux_manage":"1689211844","rpc_manage":"1689189079","mac":"1689210788","mac_vendor_string":"1689189077","manufacturer_classification":"1689189197","hostname":"1689155054","guest_corporate_state":"1689093790","is_logged_in":"1689199547","nbthost":"1689189227","va_os":"1689189201","cl_type":"1689189197","os_cpe":"1689189201","vendor":"1689189077","membership_type":"1689189090","prim_classification":"1689189197","vpn_login":"1689189077","vmware_guest_os":"1689189077","wmi_port":"1689189197","vendor_classification":"1689189197","va_os_comp":"1689189201","nbtdomain":"1689199548","va_os_cpe":"1689189201","linux_appliance_ip":"1689189077","segment_path":"1689189077","primary_key":"1689211870","agent_version":"1689078518","smb_manage":"1689189078","manage_agent":"1689189077","model_classification":"1689189197","cached_credentials":"1689211726","osx_appliance_ip":"1689189077","online":"1689211726","va_netfunc":"1689189197","fsprocsvc_owner_sid":"1689189082","os_details_classification":"1689189201"}', 'windows_updates_waiting_for_reboot': 'false', 'rpc_manage': 'true', 'mac': '000c2945476c', 'manufacturer_classification': 'VMware', 'nbthost': 'POD10-SPLUNK-01', 'is_logged_in': 'false', 'va_os': 'Windows Server 2019 64-bit', 'vendor': 'vmware, inc.', 'os_cpe': 'cpe:2.3:o:microsoft:Windows_Server_2019_64-bit:-::-:*::*:*:*', 'connect_assigned_appliance': '', 'membership_type': 'Domain', 'vmware_guest_os': 'windows2019srv_64Guest', 'vpn_login': 'false', 'prim_classification': 'Information Technology/Computer', 'connect_acttst_password': '', 'vendor_classification': 'VMware/VMware Virtual Machine', 'connect_api_rate_limit_unit': '1', 'nbtdomain': 'POD10', 'va_os_cpe': 'cpe:2.3:o:microsoft:Windows_Server_2019_64-bit:-::-:*::*:*:*', 'linux_appliance_ip': '10.110.1.61', 'segment_path': '/Segments/UCY-LAB Internal Network/In-Scope/DC1', 'primary_key': '10.210.20.163', 'connect_authorization_token': 'eyJhbGciOiJIUzUxMiJ9.eyJhcHBfbmFtZSI6IiIsInN1YiI6ImxvY2FsYWNjb3VudCIsImlhdCI6MTY4OTIxMTUyMiwiZXhwIjoxNjg5Mjk3OTIyLCJyb2wiOlsiUk9MRV9VU0VSIl19.TiuIuIKgEaTGLaitnGNv8V0xLiaNiW4NZDtQu3nNestl-FgyN1UYLd0n-5E8W3EfSj0t3JlKrM2L9kd21SpSqw', 'connect_instance_is_default': 'true', 'agent_version': 'None', 'manage_agent': 'false', 'smb_manage': 'true', 'acttst_action_1_list_param': 'c2c_policy_set_groups_p1', 'connect_device_password': '[connect_acttst_password]', 'osx_appliance_ip': '10.110.1.61', 'cached_credentials': 'jwilson@POD10.LAB.UPSTARTCYBER.COM::', 'online': 'true', 'connect_app_device_id': '51110948-d0b5-486c-a14f-fa5ac9d2d0e8', 'fsprocsvc_owner_sid': 'jwilson@pod10.lab.upstartcyber.com_1_5_s-1-5-32-544', 'va_netfunc': 'Windows Machine', 'os_details_classification': '{"flavor":null,"parent":"Windows Server 2019 64-bit","build":"17763.737","arch":"64-bit","sp":null,"version":"1809"}','hwi_computer': '[{"total_physical_memory":"8191.03125","user_name":"POD10\\\\jwilson","roles":"LM_Workstation,LM_Server,NT","caption":"POD10-WKS-12","description":"AT\\/AT COMPATIBLE","OEM_string_array":"[MS_VM_CERT\\/SHA1\\/27d66596a61c48dd3dc7216fd715126e33f59ae7],Welcome to the Virtual Machine","manufacturer":"VMware, Inc.","keyboard_password_status":"3","primary_owner_name":"Pod10","bootup_state":"Normal boot","part_of_domain":"true","model":"VMware7,1","thermal_state":"3","pc_system_type":"1","workgroup":null,"power_management_supported":"false","power_supply_state":"3","primary_owner_contact":null,"domain_role":"1","power_state":"0","number_of_processors":"2","support_contact_description":null,"system_type":"x64-based PC","domain":"pod10.lab.upstartcyber.com","current_time_zone":"-240","name":"POD10-WKS-12","status":"OK"}]', 'in-group': '["group1","group2"]'}

# params = {'acttst_action_1_boolean_param': 'true', 'connect_acttst_hwi_disk': '[{"acttst_hwi_disk_med_type":"12","acttst_hwi_disk_status":"OK","acttst_hwi_disk_availability":null,"acttst_hwi_disk_name":"C:","acttst_hwi_disk_size":"152971.31640625","acttst_hwi_disk_fsys":"NTFS","acttst_hwi_disk_dev_id":"C:","acttst_hwi_disk_volume_desc":"Local Fixed Disk","acttst_hwi_disk_type":"3","acttst_hwi_disk_free_space":"120790.38671875","acttst_hwi_disk_volume_name":null},{"acttst_hwi_disk_med_type":"11","acttst_hwi_disk_status":null,"acttst_hwi_disk_availability":null,"acttst_hwi_disk_name":"D:","acttst_hwi_disk_size":"4387.130859375","acttst_hwi_disk_fsys":"UDF","acttst_hwi_disk_dev_id":"D:","acttst_hwi_disk_volume_desc":"CD-ROM Disc","acttst_hwi_disk_type":"5","acttst_hwi_disk_free_space":"0.0","acttst_hwi_disk_volume_name":"ESD-ISO"}]', 'mac_vendor_string': 'VMWARE, INC.', 'hostname': 'POD10-WKS-22.pod10.lab.upstartcyber.com', 'guest_corporate_state': 'CORPORATE', 'cl_type': 'Managed', 'connect_app_device_parent': 'connect_acttst', 'connect_focal_appliance': '0', 'wmi_port': '135:1689236073', 'va_os_comp': '{"internal_version_number":"2009","flavor":"Professional","parent":"Windows 10 64-bit","os_build_number":"19044.2604","sp":null,"architecture":"64-bit"}', 'ip': '10.210.20.166', 'active': '1689254028', 'acttst_action_1_string_multi_param': 'Put what you want here ;) x2', 'connect_acttst_url': 'N/A', 'connect_authorization': '60', 'acttst_action_1_int_param': '0', 'acttst_action_1_string_param': 'Put what you want here ;)', 'connect_api_rate_limit': '10', 'model_classification': 'Virtual Machine', 'connect_cert_validation': 'false', 'connect_acttst_username': '', 'os_classification': 'Windows/Windows 10/Windows 10 Professional', '_timeinfo': '{"os_classification":"1689119403","windows_updates_waiting_for_reboot":"1689174999","rpc_manage":"1689174999","mac":"1689254028","mac_vendor_string":"1689119403","manufacturer_classification":"1689119403","hostname":"1689119403","guest_corporate_state":"1689119403","is_logged_in":"1689119403","nbthost":"1689119403","va_os":"1689119403","cl_type":"1689119403","os_cpe":"1689119403","vendor":"1689119403","membership_type":"1689119404","connect_acttst_focal_appliance":"1689219715","prim_classification":"1689119403","vmware_guest_os":"1689166839","wmi_port":"1689236073","vendor_classification":"1689119403","va_os_comp":"1689119403","nbtdomain":"1689119403","va_os_cpe":"1689119403","linux_appliance_ip":"1689119403","segment_path":"1689119403","primary_key":"1689255177","smb_manage":"1689174999","manage_agent":"1689174997","model_classification":"1689119403","cached_credentials":"1689119403","osx_appliance_ip":"1689119403","online":"1689119403","va_netfunc":"1689119403","fsprocsvc_owner_sid":"1689119403","os_details_classification":"1689119403"}', 'windows_updates_waiting_for_reboot': 'false', 'rpc_manage': 'true', 'mac': '000c291df397', 'manufacturer_classification': 'VMware', 'nbthost': 'POD10-WKS-22', 'is_logged_in': 'false', 'va_os': 'Windows 10 64-bit Professional', 'vendor': 'vmware, inc.', 'os_cpe': 'cpe:2.3:o:microsoft:Windows_10_64-bit:2009:-:-:*:Professional:*:*:*', 'connect_assigned_appliance': '', 'connect_acttst_focal_appliance': '0', 'membership_type': 'Domain', 'vmware_guest_os': 'windows9_64Guest', 'prim_classification': 'Information Technology/Computer/Workstation', 'connect_acttst_password': '********', 'vendor_classification': 'VMware/VMware Virtual Machine', 'connect_api_rate_limit_unit': '1', 'nbtdomain': 'POD10', 'va_os_cpe': 'cpe:2.3:o:microsoft:Windows_10_64-bit:2009:-:-:*:Professional:*:*:*', 'linux_appliance_ip': '10.110.1.61', 'segment_path': '/Segments/UCY-LAB Internal Network/In-Scope/DC1', 'primary_key': '10.210.20.166', 'connect_authorization_token': 'eyJhbGciOiJIUzUxMiJ9.eyJhcHBfbmFtZSI6IiIsInN1YiI6ImxvY2FsYWNjb3VudCIsImlhdCI6MTY4OTI1MjA2MCwiZXhwIjoxNjg5MzM4NDYwLCJyb2wiOlsiUk9MRV9VU0VSIl19.EgHnKiunJOggXB5ubySGDHYtGdzoN2a9TfmB9T93HEUrhTIDUtcIEJt6L4DYbeVm0lauOkKwSOmhZPfDgv14lg', 'connect_instance_is_default': 'true', 'manage_agent': 'false', 'smb_manage': 'true', 'acttst_action_1_list_param': 'c2c_policy_set_groups_p1', 'connect_device_password': '[connect_acttst_password]', 'osx_appliance_ip': '10.110.1.61', 'cached_credentials': 'jwilson@POD10.LAB.UPSTARTCYBER.COM::', 'online': 'true', 'connect_app_device_id': '0fa0d937-b613-48a0-9280-073ccd06a06f', 'fsprocsvc_owner_sid': 'jwilson@pod10.lab.upstartcyber.com_1_5_s-1-5-32-544', 'va_netfunc': 'Windows Machine', 'os_details_classification': '{"flavor":"Professional","parent":"Windows 10 64-bit","build":"19044.2604","arch":"64-bit","sp":null,"version":"2009"}'}
# <--! end testing params area !-->




def parse_params(subfields_dict, fs_tag, pams):
    connect_hwi_disk_val = []
    response = {}
    properties = {}
    if params.get(fs_tag):
        try:    
            # <--! uncomment below for prod !-->
            disks_array = json.loads(str(params.get(fs_tag)))
            # <--! uncomment above for prod !-->

            # <--! temporary dev placeholder begin !-->
            # hwi_disk = {'hwi_disk': '[{"drive_type":"5","file_system":"UDF","size":"5051.33984375","device_id":"D:","media_type":"11","name":"D:","volume_name":"SSS_X64FREE_EN-US_DV9","description":"CD-ROM Disc","availability":null,"free_space":"0.0","status":null},{"drive_type":"3","file_system":"NTFS","size":"204183.99609375","device_id":"C:","media_type":"12","name":"C:","volume_name":null,"description":"Local Fixed Disk","availability":null,"free_space":"178736.26171875","status":"OK"}]'}
            # initial_val = hwi_disk.get('hwi_disk')
            subfield_tags = [i for i in subfields_dict.keys()]
            param_tags = [i.get('tag') for i in subfields_dict.values()]
            parser_dict = dict(zip(subfield_tags, param_tags))
            for disk_obj in disks_array:
                disk_obj_val = {}
                for app_subfield_tag in parser_dict.keys():
                    key = parser_dict.get(app_subfield_tag)
                    if disk_obj.get(key) is not None:
                        disk_obj_val[app_subfield_tag] = disk_obj.get(key)
                connect_hwi_disk_val.append(disk_obj_val)
            properties['connect_acttst_hwi_disk'] = connect_hwi_disk_val
            response['properties'] = properties
            response['succeeded'] = True
            return connect_hwi_disk_val
            # return response
        except json.decoder.JSONDecodeError as e:
            logging.critical('Exception in acttst_action_1.py: JSONDecodeError: {}'.format(e))
            # response['troubleshooting'] = 'Exception in acttst_action_1.py: JSONDecodeError: {}'.format(e)
            # response['succeeded'] = False
            return None

response = {}
properties = {}

hwi_disk_subfields_dict = {
    'acttst_hwi_disk_name': {'type':'string', 'tag':'name'},
    'acttst_hwi_disk_size': {'type':'string', 'tag':'size'},
    # 'acttst_hwi_disk_vendor': {'type':'string', 'tag':''},
    'acttst_hwi_disk_type': {'type':'string', 'tag':'drive_type'},
    'acttst_hwi_disk_status': {'type':'string', 'tag':'status'},
    'acttst_hwi_disk_fsys': {'type':'string', 'tag':'file_system'},
    'acttst_hwi_disk_dev_id': {'type':'string', 'tag':'device_id'},
    'acttst_hwi_disk_med_type': {'type':'string', 'tag':'media_type'},
    'acttst_hwi_disk_free_space': {'type':'string', 'tag':'free_space'},
    'acttst_hwi_disk_availability': {'type':'string', 'tag':'availability'},
    'acttst_hwi_disk_volume_name': {'type':'string', 'tag':'volume_name'},
    'acttst_hwi_disk_volume_desc': {'type':'string', 'tag':'description'}
}
# connect_hwi_disk_val = []
# if connect_hwi_disk_val is not None:
    # connect_hwi_disk_val = parse_params(hwi_disk_subfields_dict, 'hwi_disk', params)
    # if len(connect_hwi_disk_val) > 0:
        # properties['connect_acttst_hwi_disk'] = connect_hwi_disk_val

connect_hwi_disk_val = parse_params(hwi_disk_subfields_dict, 'hwi_disk', params)
if connect_hwi_disk_val is not None:
    if len(connect_hwi_disk_val) > 0:
        properties['connect_acttst_hwi_disk'] = connect_hwi_disk_val


hwi_computer_subfields_dict = {
    'acttst_hwi_computer_total_physical_memory': {'type':'string', 'tag':'total_physical_memory'},
    'acttst_hwi_computer_user_name': {'type':'string', 'tag':'user_name'},
    'acttst_hwi_computer_model': {'type':'string', 'tag':'model'},
    # 'acttst_hwi_computer_model': {'type':'string', 'tag':''},
    'acttst_hwi_computer_thermal_state': {'type':'string', 'tag':'thermal_state'},
    'acttst_hwi_computer_pc_system_type': {'type':'string', 'tag':'pc_system_type'},
    'acttst_hwi_computer_workgroup': {'type':'string', 'tag':'workgroup'},
    'acttst_hwi_computer_power_management_supported': {'type':'string', 'tag':'power_management_supported'},
    'acttst_hwi_computer_power_supply_state': {'type':'string', 'tag':'power_supply_state'},
    'acttst_hwi_computer_primary_owner_contact': {'type':'string', 'tag':'primary_owner_contact'},
    'acttst_hwi_computer_domain_role': {'type':'string', 'tag':'domain_role'},
    'acttst_hwi_computer_power_state': {'type':'string', 'tag':'power_state'},
    'acttst_hwi_computer_number_of_processors': {'type':'string', 'tag':'number_of_processors'},
    'acttst_hwi_computer_support_contact_description': {'type':'string', 'tag':'support_contact_description'},
    'acttst_hwi_computer_system_type': {'type':'string', 'tag':'system_type'},
    'acttst_hwi_computer_domain': {'type':'string', 'tag':'domain'},
    'acttst_hwi_computer_current_time_zone': {'type':'string', 'tag':'current_time_zone'},
    'acttst_hwi_computer_name': {'type':'string', 'tag':'name'},
    'acttst_hwi_computer_status': {'type':'string', 'tag':'status'}
}

connect_hwi_computer_val = parse_params(hwi_computer_subfields_dict, 'hwi_computer', params)
if connect_hwi_computer_val is not None:
    if len(connect_hwi_computer_val) > 0:
        properties['connect_acttst_hwi_computer'] = connect_hwi_computer_val

# <--! comp_application area !-->
comp_application_subfield_dict = {
    'acttst_app_name': {'type':'string', 'tag':'app_name'},
    'acttst_app_version': {'type':'string', 'tag':'app_versio'},
    'acttst_app_user': {'type':'string', 'tag':'app_userl'},
}
connect_comp_application_val = parse_params(comp_application_subfield_dict, 'comp_application', params)
if connect_comp_application_val is not None:
    if len(connect_comp_application_val) > 0:
        properties['connect_acttst_comp_application'] = connect_comp_application_val

if params.get('in-group'):
    logging.critical('IN GROUP FOUND IN PARAMS: {}'.format(params))
    try:
        connect_acttst_in_group = json.loads(str(params.get('in-group')))
        logging.critical('in group: {}'.format(connect_acttst_in_group))
        properties['connect_acttst_in_group'] = connect_acttst_in_group
    except json.decoder.JSONDecodeError as e:
        logging.critical('JSONDecodeError in acttst_action_1.py: {}'.format(str(e)))

if params.get('acttst_action_2_compliance_category') or params.get('acttst_action_2_compliance_result'):
    compliance_property = {}
    if params.get('acttst_action_2_compliance_result'):
        compliance_result = params.get('acttst_action_2_compliance_result')
        compliance_property['acttst_compliance_result'] = str(compliance_result).strip()
    if params.get('acttst_action_2_compliance_category'):
        compliance_category = params.get('acttst_action_2_compliance_category')
        compliance_property['acttst_compliance_category'] = str(compliance_category).strip()
    properties['connect_acttst_compliance'] = compliance_property

# if params.get('hwi_disk'):
#     try:    
#         # <--! uncomment below for prod !-->
#         disks_array = json.loads(str(params.get('hwi_disk')))
#         # <--! uncomment above for prod !-->

#         # <--! temporary dev placeholder begin !-->
#         # hwi_disk = {'hwi_disk': '[{"drive_type":"5","file_system":"UDF","size":"5051.33984375","device_id":"D:","media_type":"11","name":"D:","volume_name":"SSS_X64FREE_EN-US_DV9","description":"CD-ROM Disc","availability":null,"free_space":"0.0","status":null},{"drive_type":"3","file_system":"NTFS","size":"204183.99609375","device_id":"C:","media_type":"12","name":"C:","volume_name":null,"description":"Local Fixed Disk","availability":null,"free_space":"178736.26171875","status":"OK"}]'}
#         # initial_val = hwi_disk.get('hwi_disk')
#         subfield_tags = [i for i in subfields.keys()]
#         param_tags = [i.get('tag') for i in subfields.values()]
#         parser_dict = dict(zip(subfield_tags, param_tags))
#         for disk_obj in disks_array:
#             disk_obj_val = {}
#             for app_subfield_tag in parser_dict.keys():
#                 key = parser_dict.get(app_subfield_tag)
#                 if disk_obj.get(key) is not None:
#                     disk_obj_val[app_subfield_tag] = disk_obj.get(key)
#             connect_hwi_disk_val.append(disk_obj_val)
#         properties['connect_acttst_hwi_disk'] = connect_hwi_disk_val
#         response['properties'] = properties
#         response['succeeded'] = True
#     except json.decoder.JSONDecodeError as e:
#         logging.critical('Exception in acttst_action_1.py: JSONDecodeError: {}'.format(e))
#         response['troubleshooting'] = 'Exception in acttst_action_1.py: JSONDecodeError: {}'.format(e)
#         response['succeeded'] = False



# if params.get('hwi_computer'):
#     try:
#         computer_array = json.loads(str(params.get('hwi_computer')))

#     except json.decoder.JSONDecodeError as e:
#         logging.critical('Exception in acttst_action_1.py: JSONDecodeError: {}'.format(e))
#         response['troubleshooting'] = 'Exception in acttst_action_1.py: JSONDecodeError: {}'.format(e)
#         response['succeeded'] = False

    # <--! temporary dev placeholder end !-->

logging.debug(params)


response['succeeded'] = True
response['properties'] = properties # - optional
logging.debug(response)

# response['troubleshooting'] = 'Oh no ;(' - optional
# response['cookie'] = 123456789 - optional
