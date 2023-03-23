# PaloAlto-Migration-Tool
Tool to migrate access rules from Palo-Alto Firewall to OCI Firewall



[BRIEF-DESCRIPTION-OF-THE-TOOL]:

This scripts uses , Palo Alto - Next Generation firewall - Running-config.xml file and converts them to OCI Network firewalls IP address , Application and Security Rules. This is essentially a data converter tool.

Refer - "Save and Export Firewall Configurations" in PAN-OS® Administrator’s Guide. Please note - a running-config.xml needs to be exported , this will be used as input by the tool.Then later converted to OCI Network Firewall rules. To know more refer : [(https://docs.paloaltonetworks.com/pan-os/9-1/pan-os-admin/firewall-administration/manage-configuration-backups/save-and-export-firewall-configurations)]

[INSTALLATION-INSTRUCTIONS]:

    Python needs to be installed in your machine , to run this code. Refer to this link for installing python on your workstation. [https://realpython.com/installing-python/]

    Download the running-config.xml file. Move the Script to the same path , as **"running-config.xml" ** rename it to **"config.xml"**. Then Execute the Python script, from that path.
    
    There are 3 python scripts - 
    
    **"PaloAlto-Migration.py"** is the main script , that provides user an interactive option to run the migration. Migration happens in 2 steps , first the config.xml gets converted to OCI Network Firewall.Json files. 
    If you are using App-ID in the access rules - instead of Services with port & protocol. Then those app list gets exported to an excel file . Similarly PaloAlto allows you to add "IP-Address" to a rule , without creating an IP address object. Both IP Address & App list are exported to missing_items.xlsx. This missing_items.xlsx is where you will have to manually update the IP address , port & protocol of services. [Please read the instructions to update missing_items.xlsx ,which is given as a seperate note.
    
    **"PA-Covert.py"** is the script , that converts the config.xml to OCI firewall JSON files. Also generates an excel file - called missing_items.xlsx as mentioned above
    
    **"PA-Install.py"** is the script , that uses "missing_items.xlsx" as input makes changes to OCI Network firewall JSON files. Installs them to OCI (Provided you have OCI CLI configured)

[USAGE-INSTRUCTIONS]:

    If OCI CLI is installed in your machine , then the script lets you to even create a firewall policy & pushes the policy to your OCI tenancy [OCI Network Firewall]. refer this link , if you would like to get OCI CLI insalled. [https://docs.oracle.com/en-us/iaas/Content/API/Concepts/cliconcepts.htm]

    If OCI CLI is not installed , then the JSON files can be copied to OCI Web CLI (Available in your OCI console), then execute OCI CLI commands for Network firewalls to create / update the firewall policies ,using the JSON files created by the script as input. Refer this link , if you would like to know the commands required to create / update - Network Firewall Policy. Refer:[https://docs.oracle.com/en-us/iaas/tools/oci-cli/3.14.0/oci_cli_docs/cmdref/network-firewall.html]

    To covert the Palo Alto Firewall Policies - You can open the terminal or command prompt on your Mac or Windows computer and type "python3" followed by the name of the Python file you want to run. In our case, it will be python3 PaloAlto-Migration.py (run from the path were , config.xml file are saved) Note:Please remember to rename the palo alto configuration xml file to **"config.xml"** , before running the script.

[EXAMPLE-OUTPUT]

~Projects-Python/default/PaloAlto-Migration.py

Please use this tool to convert - Palo Alto Firewall rules to OCI Network Firewall rules

Select an option:
1. Convert rules
2. Install rules to OCI Firewall
3. Exit

Enter option number: 1
Executing Python script A to convert rules...
Coversion Done!! Review the missing_items.xlsx , update the IP-Address or Service columns without fail!

Select an option:
1. Convert rules
2. Install rules to OCI Firewall
3. Exit

Enter option number: 2
Executing Python script B to install rules to OCI Firewall...
Enter compartment OCID: ocid1.compartment.oc1..aaaaaaaag6rhhowptbwftmpg43xddlnpiay5jo4fdnwvyzl5wcxvtn243p3a
Enter display name: DEFAULT
Enter profile name: DEFAULT
Wait while your new firewall policy is getting created :
{
  "opc-work-request-id": "ocid1.networkfirewallworkrequest.oc1.ap-hyderabad-1.amaaaaaadrm45caacq5wdsbkvhczuv2uu3mb2qnmppeaokvsmpwgupcorhsa"
}
Wait while your IP-Address-List is getting updated..
{
  "opc-work-request-id": "ocid1.networkfirewallworkrequest.oc1.ap-hyderabad-1.amaaaaaadrm45caay3nzv2hxfgdsgvqaeiomzwe3do2mkiwwv2mq2mniy3xa"
}
Wait while your Application-List is getting updated..
{
  "opc-work-request-id": "ocid1.networkfirewallworkrequest.oc1.ap-hyderabad-1.amaaaaaadrm45caacfdby6ogwapxpw3tpad4gndv3rxab2xwfxnv4xney7qa"
}
Wait while your Security-rules are getting updated..

Select an option:
1. Convert rules
2. Install rules to OCI Firewall
3. Exit
Enter option number: 3
Exiting...

[CODE-DESIGN-INFO]

**PaloAlto-Migration.py**
    1. Provides two options ( 1. To convert the rules , 2. Install the rules, 3. Exit)
    2. Option 1 : Executes PA-Convert.py
    3. Option 2 : Executes PA-Install.py
    4. Option 3 : Exit

**PA-Convert.py**
    1.Function to Sanitize Objects Names - Just the Way OCI Network firewall likes is created.
    2.Palo Alto Config.xml file is loaded.
    3.IP-Address objects , IP-Address groups , IP-ranges details from config.xml are converted to IP-Address.json
    4.service objects , Service groups - that has Port / Protocol information are converted to Apps-List.json
    5.security_rules.json gets created with source , destination , applications extracted from the config.xml (security-rules section)
    6.compare the IP-Address.json , Apps-List.json with security-rules.json. Export the IP Address & Application that are in the security rules but not in the other two Json, to an excel sheet called "missing_items.xlsx"
    
**PA-Install.py**
   1. Read "missing_items.xlsx" an make corrections to App-List.json and create Application-List.json
   2. Read "missing_items.xlsx" an make corrections to IP-Address.json and create IP-Address-List.json
   3. Identify security rules , that has mix of ICMP & TCP / UDP based applications. Create them as seperate rules , as OCI firewall will not let create access rules with ICMP and non-ICMP applications. Then create Security_Rules_v2.json 
   4. Finally create a Firewall policy in OCI , and push the json files - using the OCI CLI integration.**(If available!)**



[KNOWN-ISSUES]

    1. This tool uses xml file , from the PaloAlto firewall as input. If their xml format changes , that means some part of this code needs to change.
    2. This version of code , foucses only on Firewall access rules , and threat prevention rules , PBR  are not exported as part of this code.
    3. You may also want to review, the features used in PaloAlto firewall & OCI Network Firewall. The native firewall of OCI is pretty lean. [It is not expected to behave - as NAT , VPN , Proxy or a Routing device]. Such capabilites , when you choose to use OCI Network Firewall, will be migrated to other native services. So those  rules will not be part of this migration.
    4. missing_items.xlsx will list the IP address objectnames & Service Objectnames - that are "missing" from the IP Address & applications list. These details must be captured manually in excel. The code does not do any format check of the input , if you enter the IP address or Service details incorrectly. The policy will failed to get installed.

refer sample - missing_details.xls , and a note to explain how to update the sheet.
