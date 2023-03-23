import xml.etree.ElementTree as ET
import json, re, os, copy
import pandas as pd
from ipaddress import ip_address, ip_network, summarize_address_range

#######################################################################################################
####################FUNCTION TO SANITZE NAMES - JUST THE WAY OCI FIREWALL LIKES########################
#######################################################################################################

def sanitize_name(name):
    # Trim the name to 28 characters
    name = name[:28]
    # Remove spaces in the name
    name = name.replace(' ', '')
    # Add the "IP_" prefix if the name starts with a number
    if name[0].isdigit():
        name = "IP_" + name
    # Replace "." with "_" and "/" with "-"
    name = name.replace(".", "_").replace("/", "-")
    # Check if the name ends with a special character
    special_char_pattern = r'[^a-zA-Z0-9]'
    if re.search(special_char_pattern, name[-1]):
        name = name[:-1]
    return name

########################################################################################################
############################### LOAD THE PALO ALTO CONFIG XML FILE######################################
########################################################################################################
# Load the XML file
tree = ET.parse('config.xml')

# Get the root element
root = tree.getroot()

#######################################################################################################
################# CONVERT PALO ALTO - CONFIG.XML TO OCI-FIREWALL IP ADDRESS LIST JSON##################
#######################################################################################################

# Find the security element that contains an addresses element
addresses_element = None
for elem in root.iter():
    if elem.tag == 'address':
        addresses_element = elem
        break

# Extract the IP addresses and names as dictionaries
ip_address_dict = {}
for entry in addresses_element.iter('entry'):
    name = sanitize_name(entry.get('name'))
    ip_elem = entry.find('ip-netmask')
    if ip_elem is not None:
        ip_addr = ip_elem.text
        ip_address_dict[name] = [ip_addr]

# Extract the IP Range and names as dictionaries
    iprange_elem = entry.find ('ip-range')
    if iprange_elem is not None:
        ip_addr = iprange_elem.text
        # Check if the IP range value is a range
        if '-' in ip_addr:
            #Split the range into minimum and maximum values
            firstip, lastip = ip_addr.split('-')
            first = ip_address(firstip)
            last = ip_address(lastip)

# Calculate a list of IP network objects that cover the range of IP addresses
            ip_network_objects = list(summarize_address_range(first, last))
            ip_address_dict[name] = [str(ip) for ip in ip_network_objects]


# Find the security element that contains an address-group element
address_group_element = None
for elem in root.iter():
    if elem.tag == 'address-group':
        address_group_element = elem
        break

# Extract the IP addresses and names from the address-group elements as dictionaries
for entry in address_group_element.iter('entry'):
    name = sanitize_name(entry.get('name'))
    members = entry.find('static')
    ip_list = []
    for member in members.iter('member'):
        # Sanitize the member text
        member_name = sanitize_name(member.text)
        # Check if the member name exists in the ip_address_dict
        if member_name in ip_address_dict:
            ip_list += ip_address_dict[member_name]
    ip_address_dict[name] = ip_list

# Write the data to a JSON file
with open('IP-Address.json', 'w') as f:
    json.dump(ip_address_dict, f, indent=4)

#######################################################################################################
################# CONVERT PALO ALTO - CONFIG.XML TO OCI-FIREWALL APPLICATION LIST JSON#################
#######################################################################################################
# Find the security element that contains a services element
services_element = None
for elem in root.findall(".//devices/entry/vsys/entry/service"):
    services_element = elem
    break

# Extract the services and protocols as dictionaries
services_dict = {}
for entry in services_element.iter('entry'):
    name = sanitize_name(entry.get('name'))
    protocol_elem = entry.find('protocol')
    protocol_type = None
    port_list = []
    if protocol_elem is not None:
        if protocol_elem.find('tcp') is not None:
            protocol_type = 'TCP'
            port_elem = protocol_elem.find('tcp/port')
            if port_elem is not None:
                port = port_elem.text
                if '-' in port:
                    start_port, end_port = port.split('-')
                    port_list.extend(range(int(start_port), int(end_port) + 1))
                else:
                    port_list.append(int(port))
        elif protocol_elem.find('udp') is not None:
            protocol_type = 'UDP'
            port_elem = protocol_elem.find('udp/port')
            if port_elem is not None:
                port = port_elem.text
                if '-' in port:
                    start_port, end_port = port.split('-')
                    port_list.extend(range(int(start_port), int(end_port) + 1))
                else:
                    port_list.append(int(port))
    if protocol_type is not None:
        service_data = {
            'type': protocol_type,
            'minimum-port': min(port_list),
            'maximum-port': max(port_list)
        }
        services_dict[name] = [service_data]

# Handle service groups
for entry in root.findall(".//devices/entry/vsys/entry/service-group/entry"):
    group_name = sanitize_name(entry.get('name'))
    members_elem = entry.find('members')
    if members_elem is not None:
        members = members_elem.findall('member')
        group_services = []
        for member in members:
            member_name = sanitize_name(member.text)
            if member_name in services_dict:
                group_services.extend(services_dict[member_name])
        if len(group_services) > 0:
            services_dict[group_name] = group_services

# Write the data to a JSON file
with open('Apps-List.json', 'w') as f:
    json.dump(services_dict, f, indent=4)

########################################################################################################
################## CONVERT PALO ALTO - CONFIG.XML TO OCI-FIREWALL SECURITY RULES JSON###################
########################################################################################################

# Find the security element that contains a rules element
security_element = None
for elem in root.iter():
    if elem.tag == 'security':
        if any(child.tag == 'rules' for child in elem):
            security_element = elem
            break

# Extract the source and destination elements as dictionaries
rules =[]
urls = []
inspection = None
# Initialize a counter variable to keep track of the index
counter = 1
for entry in security_element.iter('entry'):
    # Set the "name" field to "rule-number-X", where X is the index of the item in the list
    name = "rule-number-{}".format(counter)
    # Increment the counter variable
    counter += 1
    # Extract the source, destination, service, and action attributes
    source_elem = entry.find('source')
    if source_elem is not None:
        member_elems = source_elem.findall('member')
        if member_elems:
            sources = [sanitize_name(member.text) for member in member_elems]
        else:
            sources = [sanitize_name(source_elem.text)]
        # Check if sources is "any", replace with empty list if it is
        if sources == ['any']:
            sources = [] 
    dest_elem = entry.find('destination')
    if dest_elem is not None:
        member_elems = dest_elem.findall('member')
        if member_elems:
            destinations = [sanitize_name(member.text) for member in member_elems]
        else:
            destinations = [sanitize_name(dest_elem.text)]
        # Check if destinations is "any", replace with empty list 
        if destinations == ['any']:
            destinations = [] 
    serv_elem = entry.find('service')
    if serv_elem is not None:
        member_elems = serv_elem.findall('member')
        if member_elems:
            services = [sanitize_name(member.text) for member in member_elems]
        else:
            services = [sanitize_name(serv_elem.text)]
    application_elem = entry.find('application')
    if application_elem is not None:
        member_elems = application_elem.findall('member')
        if member_elems:
            applications = [sanitize_name(member.text) for member in member_elems]
        else:
            applications = [sanitize_name(application_elem.text)]
    
    # Merge the services and applications lists        
    services_and_apps = services + applications

    # Remove 'any' and 'application-default' from the services and applications list
    services_and_apps = [sa for sa in services_and_apps if sa not in ['any', 'application-default']]

    action_elem = entry.find('action')
    if action_elem is not None:
        action = sanitize_name(action_elem.text)
        if action == 'allow': 
            action = 'ALLOW'
        elif action == 'deny':
            action = 'DROP'


    # Combine the source and destination elements into a conditions dictionary
    conditions = {'applications': services_and_apps, 'destinations': destinations, 'sources': sources, 'urls': urls}
    
    # Combine the name, action, and conditions into a dictionary
    rule = {'action': action, 'condition': conditions, 'inspection': inspection, 'name': name}
    
    # Append the rule to the list of rules
    rules.append(rule)

# Write the data to a JSON file
with open('security-rules.json', 'w') as f:
    json.dump(rules, f, indent=4)

#######################################################################################################################
#### COMPARE AND LOG THE DIFFERENCE , BETWEEN RULES AND IP ADDRESS & SERVICES##########################################
#######################################################################################################################

# Load the security-rule JSON file
with open('security-rules.json', 'r') as f:
    data1 = json.load(f)

# Load the IP-Address JSON file
with open('IP-Address.json', 'r') as f:
    data2 = json.load(f)

# Load the App-List JSON file
with open('Apps-List.json', 'r') as f:
    data3 = json.load(f)

# Extract the list of key names from IP-Address JSON
keys_list = list(data2.keys())
keys_list2 = list(data3.keys())

# Initialize empty lists for missing sources and destinations
missing_sources = []
missing_destinations = []
missing_applications = []

# Check each rule in data1 for missing sources and destinations
for rule in data1:
    if 'sources' in rule['condition']:
        for source in rule['condition']['sources']:
            if source not in keys_list:
                missing_sources.append({
                    'rule-name': rule['name'],
                    'service/network': 'Missing Source',
                    'object-name': source,
                    'Address': ''
                })

    if 'destinations' in rule['condition']:
        for destination in rule['condition']['destinations']:
            if destination not in keys_list:
                missing_destinations.append({
                    'rule-name': rule['name'],
                    'service/network': 'Missing Destination',
                    'object-name': destination,
                    'Address': ''
                })
    if 'destinations' in rule['condition']:
        for application in rule['condition']['applications']:
            if application not in keys_list2:
                missing_applications.append({
                    'rule-name': rule['name'],
                    'service/network': 'Missing Application',
                    'object-name': application,
                    'Protocol': '',
                    'Port-Max': '',
                    'Port-Min': ''
                })

# Convert the lists to DataFrames
missing_sources_df = pd.DataFrame(missing_sources)
missing_destinations_df = pd.DataFrame(missing_destinations)
missing_applications_df = pd.DataFrame(missing_applications)

# Concatenate the two DataFrames
missing_df = pd.concat([missing_sources_df, missing_destinations_df, missing_applications_df], ignore_index=True)

# Reorder the columns
missing_df = missing_df[['rule-name', 'service/network', 'object-name', 'Address', 'Protocol', 'Port-Min', 'Port-Max' ]]

# Group the DataFrame by 'service/network' and 'object-name'
grouped_df = missing_df.groupby(['service/network', 'object-name'])

# Concatenate the 'rule-name' values for each group into a comma-separated string
rules = grouped_df['rule-name'].apply(lambda x: ','.join(x)).reset_index()

# Merge the concatenated rules back into the original DataFrame
missing_df = pd.merge(missing_df, rules, on=['service/network', 'object-name'], how='left')

# Rename the column containing the concatenated rules
missing_df = missing_df.rename(columns={'rule-name_x': 'rule-name', 'rule-name_y': 'rules'})

# Drop the duplicate 'rule-name' column
missing_df = missing_df.drop(columns='rule-name')

# Drop duplicate rows
missing_df = missing_df.drop_duplicates(subset=['service/network', 'object-name', 'rules'], keep='first')

# Save the DataFrame to an Excel file
missing_df.to_excel('missing_items.xlsx', index=False)

print("Coversion Done!! Review the missing_items.xlsx , update the IP-Address or Service columns without fail!")