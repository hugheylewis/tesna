from datetime import datetime, timedelta
from time import strftime, localtime
from config import config
import requests
import json


class Header:

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


def get_scanners():
    scanner_ids = {}
    scanner_header = Header(url="https://cloud.tenable.com/scans")

    headers = {
        "accept": scanner_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_header.ACCESS_KEY};secretKey={scanner_header.SECRET_KEY}"
    }

    response = requests.get(scanner_header.url, headers=headers)
    json_response = json.loads(response.text)
    for i in json_response['scans']:
        if "ADD_YOUR_SCAN_NAME_HERE_FOR_FILTERING" in i['name']:  # If you don't want to filter scans based on the name, then delete this line 
            scanner_ids[i['id']] = i['schedule_uuid']
    return scanner_ids


def get_scan_history(scan_id):
    def convert_epoch(etime):
        return strftime('%Y-%m-%d %H:%M:%S', localtime(etime))
    scan_history_ids_times = {}
    scanner_header = Header(url=f"https://cloud.tenable.com/scans/{scan_id}/history?exclude_rollover=true")

    headers = {
        "accept": scanner_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_header.ACCESS_KEY};secretKey={scanner_header.SECRET_KEY}"
    }

    response = requests.get(scanner_header.url, headers=headers)
    json_response = json.loads(response.text)
    for i in json_response['history']:
        if i['status'] == "completed":
            scan_history_ids_times[i['id']] = convert_epoch(i['time_end'])
    return scan_history_ids_times


def get_scanner_details(get_scanners_id):
    scanned_host_ids = {}
    scanner_results_header = Header(url=f"https://cloud.tenable.com/scans/{get_scanners_id}")

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
    scan_history_dict = get_scan_history(scanner_id)
    datetime_lessthan_oneweek = ''
    hid = 0
    for history_id, completed_scan_time in scan_history_dict.items():
        target_datetime = datetime.strptime(completed_scan_time, '%Y-%m-%d %H:%M:%S')
        difference = current_datetime - target_datetime
        if difference < timedelta(days=7):
            datetime_lessthan_oneweek += completed_scan_time
            hid += history_id

    scanner_results_header = Header(
        url=f"https://cloud.tenable.com/scans/{schedule_uuid}/hosts/{asset_id}?history_id={hid}")

    headers = {
        "accept": scanner_results_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_results_header.ACCESS_KEY};secretKey={scanner_results_header.SECRET_KEY}"
    }

    response = requests.get(scanner_results_header.url, headers=headers)
    json_response = json.loads(response.text)
    for i in json_response['vulnerabilities']:
        if i['severity'] == 4:
            host_vulnerability_plugins[i['plugin_id']] = i['plugin_name']
    return host_vulnerability_plugins, datetime_lessthan_oneweek


def get_vuln_details(plugin_id):
    def filter_none_and_fixed(d):
        return {k: filter_none_and_fixed(v) if isinstance(v, dict) else v for k, v in d.items() if
                v is not None and not (k == "state" and v == "FIXED")}

    vuln_data = []
    scanner_results_header = Header(url=f"https://cloud.tenable.com/workbenches/vulnerabilities/{plugin_id}/info")

    headers = {
        "accept": scanner_results_header.ACCEPT,
        "X-ApiKeys": f"accessKey={scanner_results_header.ACCESS_KEY};secretKey={scanner_results_header.SECRET_KEY}"
    }

    response = requests.get(scanner_results_header.url, headers=headers)
    json_response = json.loads(response.text)
    filtered_response = filter_none_and_fixed(json_response)
    # return filtered_response['info']['plugin_details']['name']
    return filtered_response['info']['plugin_details']['name'], filtered_response['info']['description'], filtered_response['info']['solution'], filtered_response['info']['see_also']


if '__main__' == __name__:
    sn_ticket_data = []
    current_datetime = datetime.now()
    scanner_ids_dict = get_scanners()
    for scanner_id, scanner_schedule_uuid in scanner_ids_dict.items():
        scanned_hosts = get_scanner_details(scanner_id)
        for device_id, hostnames in scanned_hosts.items():
            print(hostnames)
        for asset_id_key, hostname_value in scanned_hosts.items():
            host_details_dict, last_scan_date = get_host_details(scanner_schedule_uuid, asset_id_key)
            print(f"Vulnerabilities found on {hostname_value} from scan on {last_scan_date}:\n{host_details_dict}")
            for plugin_id, plugin_name in host_details_dict.items():
                name, details, solution, see_also = get_vuln_details(plugin_id)
                print(f"\t{name}\n\t{details}\n\t{solution}\n\t{see_also}\n\t")
