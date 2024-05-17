from datetime import datetime
from config import config
import requests
import json


class TenableHeader:

    ACCEPT = "application/json"
    ACCESS_KEY = config.APIkeys.access_key
    SECRET_KEY = config.APIkeys.secret_key

    def __init__(self, url):
        self._url = url

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, new_url):
        if isinstance(new_url, str):
            self._url = new_url


class MsHeader:

    ACCEPT = '"accept": "application/json"'

    def __init__(self, tenant_id, app_id, app_secret, url):
        self._tenant_id = tenant_id
        self._app_id = app_id
        self._app_secret = app_secret
        self._url = url

    @property
    def tenant_id(self):
        return self._tenant_id

    @property
    def app_id(self):
        return self._app_id

    @property
    def app_secret(self):
        return self._app_secret

    @property
    def url(self):
        return self._url

    @url.setter
    def url(self, new_url):
        if isinstance(new_url, str):
            self._url = new_url


def get_scanners():
    scanner_ids = {}
    scanner_header = TenableHeader(url="https://cloud.tenable.com/scans")

    headers = {
        "accept": scanner_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_header.ACCESS_KEY};secretKey={scanner_header.SECRET_KEY}"
    }

    response = requests.get(scanner_header.url, headers=headers)
    json_response = json.loads(response.text)
    for i in json_response['scans']:
        if "YOUR_SCANNER_PREFIX_HERE" in i['name']:  # if you're not filtering on scanner names, then delete this line
            scanner_ids[i['id']] = i['schedule_uuid']
    return scanner_ids


def get_scanner_details(get_scanners_id):
    scanned_host_ids = {}
    scanner_results_header = TenableHeader(url=f"https://cloud.tenable.com/scans/{get_scanners_id}")

    headers = {
        "accept": scanner_results_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_results_header.ACCESS_KEY};secretKey={scanner_results_header.SECRET_KEY}"
    }

    response = requests.get(scanner_results_header.url, headers=headers)
    json_response = json.loads(response.text)
    try:
        for i in json_response['hosts']:
            scanned_host_ids[i['asset_id']] = i['hostname']
    except KeyError:
        print("The key 'hosts' does not exist in the API response.")
    return scanned_host_ids


def get_host_details(schedule_uuid, asset_id):
    host_vulnerability_plugins = {}

    scanner_results_header = TenableHeader(
        url=f"https://cloud.tenable.com/scans/{schedule_uuid}/hosts/{asset_id}")

    headers = {
        "accept": scanner_results_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_results_header.ACCESS_KEY};secretKey={scanner_results_header.SECRET_KEY}"
    }

    response = requests.get(scanner_results_header.url, headers=headers)
    json_response = json.loads(response.text)

    # #TODO: Delete after done with troubleshooting
    # print(f"scan_uuid: {schedule_uuid}\nhost_id: {asset_id}")

    host_os = json_response['info']['operating-system'][0]
    host_ip = json_response['info']['host-ip']
    try:
        for i in json_response['vulnerabilities']:
            if i['severity'] == 4:
                host_vulnerability_plugins[i['plugin_id']] = i['plugin_name']
    except KeyError:
        print(f"The key 'vulnerabilities' does not exist in the API response.\n{json_response}")
    return host_vulnerability_plugins, host_os, host_ip


def get_vuln_details(pid):
    def filter_none_and_fixed(d):
        return {k: filter_none_and_fixed(v) if isinstance(v, dict) else v for k, v in d.items() if
                v is not None and not (k == "state" and v == "FIXED")}

    vuln_data = []
    scanner_results_header = TenableHeader(url=f"https://cloud.tenable.com/workbenches/vulnerabilities/"
                                               f"{pid}/info")

    headers = {
        "accept": scanner_results_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_results_header.ACCESS_KEY};secretKey={scanner_results_header.SECRET_KEY}"
    }

    response = requests.get(scanner_results_header.url, headers=headers)
    json_response = json.loads(response.text)
    filtered_response = filter_none_and_fixed(json_response)
    vuln_data.extend([filtered_response['info']['plugin_details']['name'], filtered_response['info']['description'],
                      filtered_response['info']['solution'], filtered_response['info']['see_also']])
    return vuln_data


def azure_token():
    tenant = config.APIkeys.tenant_id
    token_header = MsHeader(config.APIkeys.tenant_id, config.APIkeys.app_id, config.APIkeys.app_secret,
                            url=f"https://login.microsoftonline.com/{tenant}/oauth2/token")
    token_header.url = f"https://login.microsoftonline.com/{token_header.tenant_id}/oauth2/token"
    resource_app_id_uri = 'https://api-us.securitycenter.microsoft.com'

    body = {
        'resource': resource_app_id_uri,
        'client_id': token_header.app_id,
        'client_secret': token_header.app_secret,
        'grant_type': 'client_credentials'
    }

    req = requests.post(token_header.url, body)
    response = req.text
    json_response = json.loads(response)
    return json_response['access_token']


def get_machine_id(hostname):
    bearer_token = azure_token()

    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter=startswith(computerDnsName,'{hostname}')"
    headers = {
        f'Authorization': f'Bearer {bearer_token}'
    }

    response = requests.request("GET", url, headers=headers)
    json_response = json.loads(response.text)
    return json_response['value'][0]['id']


def get_device_owner(machine_id):
    bearer_token = azure_token()
    machine_owners = []

    url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/logonusers"
    headers = {
        f'Authorization': f'Bearer {bearer_token}'
    }

    response = requests.request("GET", url, headers=headers)
    json_response = json.loads(response.text)
    for user in json_response['value']:
        machine_owners.append(user['accountName'])
    return machine_owners


if '__main__' == __name__:
    sn_ticket_data = []
    current_datetime = datetime.now()
    scanner_ids_dict = get_scanners()
    for scanner_id, scanner_schedule_uuid in scanner_ids_dict.items():
        scanned_hosts = get_scanner_details(scanner_id)
        for device_id, hostnames in scanned_hosts.items():
            print(hostnames)
        for asset_id_key, hostname_value in scanned_hosts.items():
            host_details_dict, host_operating_system, host_ip_address = get_host_details(scanner_schedule_uuid,
                                                                                         asset_id_key)
            if host_details_dict:
                device_id = get_machine_id(hostname_value)
                device_owner = get_device_owner(device_id)
                print(f"Critical vulnerabilities found on {hostname_value} with IP {host_ip_address} affecting "
                      f"{host_operating_system} and the owner of {device_owner}:")
            else:
                print(f"No critical vulnerabilities found on {hostname_value}")
            for plugin_id, plugin_name in host_details_dict.items():
                name, details, solution, see_also = get_vuln_details(plugin_id)
                print(f"Vuln name: {name}\n\tVuln details: {details}\n\tVuln solution: {solution}\n\tMore information: "
                      f"{see_also}\n\t")
