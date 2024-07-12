from requests.auth import HTTPBasicAuth
from config import config
import requests
import json

access_key = config.APIkeys.access_key
secret_key = config.APIkeys.secret_key

hostname = input(str("Enter hostname: "))
device_owner = input(str("Enter device owner: "))

def get_device_id(hostname):
    import requests

    url = f"https://cloud.tenable.com/workbenches/assets?filter.0.filter=host.target&filter.0.quality=match&filter.0.value={hostname}"

    headers = {
        "accept": "application/json",
        f"X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    response = requests.get(url, headers=headers)
    json_response = json.loads(response.text)

    return json_response


def get_device_vulnerabilities(hostname_id):
    url = f"https://cloud.tenable.com/workbenches/assets/{hostname_id}/vulnerabilities"

    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
    }

    response = requests.get(url, headers=headers)
    json_response = json.loads(response.text)
    return json_response


def get_vuln_details(plugin_id):
    def filter_none_and_fixed(d):
        return {k: filter_none_and_fixed(v) if isinstance(v, dict) else v for k, v in d.items() if
                v is not None and not (k == "state" and v == "FIXED")}

    def get_vuln_evidence(plugin_id, device_id):
        url = f"https://cloud.tenable.com/workbenches/vulnerabilities/{plugin_id}/outputs?filter.0.filter=host.id&filter.0.quality=match&filter.0.value={device_id}"

        headers = {
            "accept": "application/json",
            "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
        }

        response = requests.get(url, headers=headers)
        json_response = json.loads(response.text)

        return json_response['outputs'][0]['plugin_output']

    vuln_data = []

    headers = {
        "accept": "application/json",
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}",
    }

    response = requests.get(f"https://cloud.tenable.com/workbenches/vulnerabilities/{plugin_id}/info", headers=headers)
    json_response = json.loads(response.text)
    filtered_response = filter_none_and_fixed(json_response)
    device_id = get_device_id(hostname)['assets'][0]['id']
    vuln_data.extend([filtered_response['info']['plugin_details']['name'], filtered_response['info']['description'], get_vuln_evidence(plugin_id, device_id),
                      filtered_response['info']['solution'], filtered_response['info']['see_also']])
    return vuln_data


def get_user_location(uname):
    query = f'user_name={uname}'
    url = f'https://YOUR_INSTANCE_HERE.service-now.com/api/now/table/sys_user?sysparm_query={query}&sysparm_limit=1'

    user = config.APIkeys.user
    pwd = config.APIkeys.pwd

    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    response = requests.get(url, auth=(user, pwd), headers=headers)

    json_response = json.loads(response.text)

    def get_building(building_url):
        username = config.APIkeys.user
        password = config.APIkeys.pwd

        building_response = requests.get(building_url, auth=HTTPBasicAuth(username, password))
        building_json_response = json.loads(building_response.text)
        return building_json_response['result']['name']

    phone_number, floor, room = (json_response['result'][0]['phone'], json_response['result'][0]['u_floor'],
                                 json_response['result'][0]['u_room'])
    return phone_number, floor, room, get_building(json_response['result'][0]['building']['link'])


def open_ticket(affected_email, affected_user, caller, short_description, description):
    phone_number, floor, room, building = get_user_location(affected_email)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}

    payload = {
        "u_affected_email": affected_email + "@YOUR_DOMAIN_HERE.com",
        "u_affected_user": affected_user,
        "u_caller": caller,
        "short_description": short_description,
        "u_service": "Vulnerability Management",
        "contact_type": "Email",
        "description": description,
        "assignment_group": "YOUR_ASSIGNMENT_GROUP_HERE",
        "u_symptom": 'YOUR_SYMPTOM_ID_HERE',
        "phone": phone_number,
        "u_building": building,
        "u_floor": floor,
        "u_room": room,
    }

    json_payload = json.dumps(payload)
    response = requests.post('https://YOUR_INSTANCE_HERE.service-now.com/api/now/table/incident',
                             auth=(config.APIkeys.user, config.APIkeys.pwd), headers=headers,
                             data=json_payload)

    if response.status_code != 200:
        print('Status:', response.status_code, 'Headers:', response.headers, 'Error Response:', response.json())
        exit()

    json_response = json.loads(response.text)
    return json_response, building


def main():
    list_of_hostname_ids = []
    all_sn_ticket_data = []

    device_owner_split_name = device_owner.split('.')
    capitalized_name = [word.capitalize() for word in device_owner_split_name]
    device_owner_full_name = ' '.join(capitalized_name)
    for i in get_device_id(hostname)['assets']:
        list_of_hostname_ids.append(i['id'])
    for device_id in list_of_hostname_ids:
        device_vulnerabilities = get_device_vulnerabilities(device_id)
        if len(device_vulnerabilities['vulnerabilities']) > 0:
            for vuln in device_vulnerabilities['vulnerabilities']:
                if vuln['severity'] == 4:
                    print(vuln)
                    name, details, evidence, solution, see_also = get_vuln_details(vuln['plugin_id'])
                    each_link = ', '.join(see_also)
                    sn_ticket_data_dict = f"Vulnerability Name: {name}\nEvidence: {evidence}\nSolution: {solution}\nMore Info: {each_link}\n"
                    all_sn_ticket_data.append(sn_ticket_data_dict)
    description = "\n".join(all_sn_ticket_data)
    sn_ticket = open_ticket(device_owner, device_owner_full_name, device_owner_full_name,
                            f"Critical vulnerabilities - {hostname}", description)
    return sn_ticket


print(main())
