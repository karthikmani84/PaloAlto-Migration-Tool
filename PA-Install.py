import pandas as pd
import json

# Read the Excel file into a DataFrame
df = pd.read_excel('missing_items.xlsx', sheet_name='Sheet1')

# Create an empty dictionary to store the IP addresses
ip_dict = {}

# Loop through the DataFrame and add IP addresses to the dictionary
for index, row in df.iterrows():
    if pd.notna(row['service/network']) and (row['service/network']== "Missing Source" or row['service/network']== "Missing Destination"):
        ip_dict[row['object-name']] = [row['Address']]

# Load the existing JSON file
with open('IP-Address.json') as json_file:
    data = json.load(json_file)

# Append the IP addresses to the JSON file
for object_name, ip_address in ip_dict.items():
    data[object_name] = ip_address

# Save the updated JSON file
with open('IP-Address-List.json', 'w') as json_file:
    json.dump(data, json_file)

# Create an empty dictionary to store the services
services_dict = {}

for index, row in df.iterrows():
    if pd.notna(row['service/network']) and row['service/network'] == "Missing Application" and row['Protocol'] == "tcp":
        min_port = int(row['Port-Min'])
        max_port = int(row['Port-Max'])
        services_data = [{
            'type': 'TCP',
            'minimum-port': min_port,
            'maximum-port': max_port
        }]
        services_dict[row['object-name']] = services_data
    elif pd.notna(row['service/network']) and row['service/network'] == "Missing Application" and row['Protocol'] == "udp":
        min_port = int(row['Port-Min'])
        max_port = int(row['Port-Max'])
        services_data = [{
            'type': 'UDP',
            'minimum-port': min_port,
            'maximum-port': max_port
        }]
        services_dict[row['object-name']] = services_data
    elif pd.notna(row['service/network']) and row['service/network'] == "Missing Application" and row['Protocol'] == "icmp":
        services_data = [
            {
              "icmp-code": None,
              "icmp-type": 0,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 3,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 5,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 8,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 9,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 10,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 11,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 12,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 13,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 14,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 40,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 42,
              "type": "ICMP"
            },
            {
              "icmp-code": None,
              "icmp-type": 43,
              "type": "ICMP"
            }
        ]
        services_dict[row['object-name']] = services_data

# Load the existing JSON file
with open('Apps-List.json') as json_file:
    data = json.load(json_file)

# Append the IP addresses to the JSON file
for object_name, services_data in services_dict.items():
    data[object_name] = services_data

# Save the updated JSON file
with open('Application-List.json', 'w') as json_file:
    json.dump(data, json_file)

import json, re, os, copy

#######################################################################################################
####################CREATE DUPLICATE RULES THAT HAS ICMP APPLICATIONS##################################
#######################################################################################################

try:
    with open("Application-List.json") as file:
        data = json.load(file)
    with open("security-rules.json") as file:
        B = json.load(file)

except FileNotFoundError as e:
    print(f"File not found: {e}")
    exit(1)
except json.decoder.JSONDecodeError as e:
    print(f"Error decoding JSON file: {e}")
    exit(1)


# Extracting non-ICMP -list
icmp_list =[]

for key in data.keys():
    for val in data[key]:
        if val['type'] == 'ICMP':
            icmp_list.append(key)
            break  # Exit the inner loop after first non-icmp type

new_rules = []
for obj in B:
    assert 'condition' in obj, f'condition key not found in object {obj}'
    new_rule = copy.deepcopy(obj)
    icmp_applications = []
    non_icmp_applications = []
    if 'applications' in obj['condition']:
        all_in_icmp_list = True  # flag to track if all applications are in icmp_list
        for application in obj["condition"]["applications"]:
            if application in icmp_list:
                icmp_applications.append(application)
            else:
                all_in_icmp_list = False  # set flag to False if any non-ICMP application is found
                non_icmp_applications.append(application)
        if all_in_icmp_list:
            new_rules.append(new_rule)  # append the unmodified rule if all applications are in icmp_list
        else:
            new_rule['condition']['applications'] = non_icmp_applications
            new_rules.append(new_rule)
            if icmp_applications:
                icmp_rule = copy.deepcopy(obj)
                icmp_rule['name'] = icmp_rule['name'] + "-icmp"
                icmp_rule['condition']['applications'] = icmp_applications
                new_rules.append(icmp_rule)
    else:
        new_rules.append(new_rule)

# Dumping the modified B object to a new json file
with open('security_rules_v2.json', 'w') as file:
    json.dump(new_rules, file, indent=2)


#######################################################################################################
#################################FINAL STEP EXECUTION##################################################
import time
import subprocess

compartment_ocid = input("Enter compartment OCID: ")
display_name = input("Enter display name: ")
profile = input("Enter profile name: ")
output = subprocess.run(["oci", "network-firewall", "network-firewall-policy", "create", "-c", compartment_ocid, "--display-name", display_name, "--profile", profile], capture_output=True)
output_str = output.stdout.decode('utf-8')
output_json = json.loads(output_str)
network_policy_ocid = output_json.get("data", {}).get("id", "")

print("Wait while your new firewall policy is getting created :")
time.sleep(15)

subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--ip-address-lists", "file://IP-Address-List.json", "--profile", profile, "--force"])
print("Wait while your IP-Address-List is getting updated..")
time.sleep(15)
    
subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--application-lists", "file://application-list.json", "--profile", profile, "--force"])
print("Wait while your Application-List is getting updated..")
time.sleep(15)
    
subprocess.run(["oci", "network-firewall", "network-firewall-policy", "update", "--network-firewall-policy-id", network_policy_ocid, "--security-rules", "file://security_rules_v2.json", "--profile", profile, "--force"])
print("Wait while your Security-rules are getting updated..")

