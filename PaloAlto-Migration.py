import subprocess

print("Please use this tool to convert - Palo Alto Firewall rules to OCI Network Firewall rules")

while True:
    print("\nSelect an option:")
    print("1. Convert rules")
    print("2. Install rules to OCI Firewall")
    print("3. Exit")

    option = input("Enter option number: ")

    if option == "1":
        print("Executing Python PA-Convert script to convert rules...")
        subprocess.call(["python", "PA-Convert.py"]) 
    elif option == "2":
        print("Executing Python  PA-Instal script to install rules to OCI Firewall...")
        subprocess.call(["python", "PA-Install.py"]) 
    elif option == "3":
        print("Exiting...")
        break
    else:
        print("Invalid option. Please try again.")
