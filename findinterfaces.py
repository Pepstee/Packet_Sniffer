# Updated findinterfaces.py

from scapy.all import conf
from scapy.arch import get_if_list # get_if_list is a more general function often available

print("Listing network interfaces using Scapy:")

# Method 1: Using conf.ifaces (often the most reliable way to access active interfaces)
print("\n--- Method 1: Using conf.ifaces ---")
if conf.ifaces:
    for iface_name in conf.ifaces:
        iface = conf.ifaces[iface_name]
        print(f"  Interface Name: {iface.name}")
        print(f"    Description: {iface.description}")
        print(f"    MAC Address: {iface.mac}")
        # if iface.ip: # Check if IP exists before printing
        #     print(f"    IP Address: {iface.ip}")
        print("    --------------------")
else:
    print("No interfaces found via conf.ifaces.")


# Method 2: Using get_if_list() (more general, but might not provide full details like conf.ifaces)
print("\n--- Method 2: Using get_if_list() ---")
try:
    interfaces = get_if_list()
    if interfaces:
        for iface in interfaces:
            print(f"  Interface: {iface}")
    else:
        print("No interfaces found via get_if_list().")
except Exception as e:
    print(f"Error using get_if_list(): {e}")

# Method 3: (If you truly need Windows-specific details and Method 1 doesn't suffice)
# Check if get_windows_if_list exists in your specific Scapy version and where it's located.
# It might be in scapy.arch.windows or similar.
# For example:
# try:
#     from scapy.arch.windows import get_windows_if_list
#     print("\n--- Method 3: Using get_windows_if_list (if available) ---")
#     windows_interfaces = get_windows_if_list()
#     for iface in windows_interfaces:
#         print(f"  Name: {iface['name']}")
#         print(f"  Description: {iface['description']}")
#         print(f"  MAC: {iface['mac']}")
#         print(f"  IPs: {iface['ips']}")
#         print("--------------------")
# except ImportError:
#     print("get_windows_if_list not found in scapy.arch.windows in this Scapy version.")
# except Exception as e:
#     print(f"Error with get_windows_if_list: {e}")

print("\nScript finished.")