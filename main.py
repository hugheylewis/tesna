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
        if "" in i['name']:  # use this to filter scans based on name
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
    for i in json_response['hosts']:
        scanned_host_ids[i['asset_id']] = i['hostname']
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


if '__main__' == __name__:
    current_datetime = datetime.now()
    scanner_ids_dict = get_scanners()
    for scanner_id, scanner_schedule_uuid in scanner_ids_dict.items():
        #TODO: add your own scanner_id value here. Remove this if statement to iterate over all scan groups, instead of just one (this is only here for small-scale testing)
        if scanner_id == YOUR_SCANNER_ID_HERE:
            scanned_hosts = get_scanner_details(scanner_id)
            print(scanned_hosts)
            for asset_id_key, hostname_value in scanned_hosts.items():
                host_details_dict, last_scan_date = get_host_details(scanner_schedule_uuid, asset_id_key)
                print(f"Vulnerabilities found on {hostname_value} from scan on {last_scan_date}:\n{host_details_dict}")
              
