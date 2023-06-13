import sys
import socket
from tabulate import tabulate
import ipaddress


def successful(text):
    """An easier way to print successful responses"""
    return f"\033[1;32m{text}\033[0m"


def error(text):
    """An easier way to print errors"""
    return f"\033[1;31m{text}\033[0m"


def binary_to_ip(binary_ip):
    """Convert a valid 32-bit value into an IPv4 address"""
    try:
        octets = [str(int(binary_ip[i:i+8], 2)) for i in range(0, 32, 8)]
        return successful(f"Decimal IP: {'.'.join(octets)}")
    except ValueError:
        return error("Error: Probably an incorrect binary value.")


def ip_to_binary(ip_address):
    """Convert an IPv4 address into its binary form"""
    try:
        ip = ipaddress.ip_address(ip_address)
        binary_ip = "{:032b}".format(int(ip))
        octets = [binary_ip[i:i+8] for i in range(0, 32, 8)]
        return successful(f"Binary IP: {'.'.join(octets)}")
    except ValueError as ip_error:
        return error(str(ip_error))


def network_address(ip_address, subnet_mask):
    """Converts an IP Subnet into its CIDR notation equivalent"""
    try:
        ip = ipaddress.IPv4Interface(f"{ip_address}/{subnet_mask}")
        return successful(f"Network address with CIDR Notation: {ip.network}")
    except ipaddress.AddressValueError:
        return error("Error: Invalid subnet mask or IP address")


def cidr_to_subnet_mask(ip_address):
    """Converts IPAddress/CIDR into dotted-decimal-notation IPAddress/Subnet Mask"""
    try:
        network = ipaddress.IPv4Network(ip_address, strict=False)
        return successful(f"Network address: {network.network_address}\nIP Subnet Mask: {network.netmask}")
    except ipaddress.AddressValueError:
        return error("Error: Invalid subnet mask or IP address")


def possible_number_of_subnets(ip_address, subnet_mask):
    try:
        ip = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False)
        return successful(f"Possible Number of Subnets: {2 ** (32 - ip.prefixlen)}")
    except ipaddress.AddressValueError:
        return error("Error: Invalid subnet mask or IP address")


def ip_class_by_hosts(ip_address, subnet_mask_or_cidr):
    try:
        subnet_mask = int(subnet_mask_or_cidr)
        cidr = subnet_mask_or_cidr
    except ValueError:
        subnet_mask = subnet_mask_or_cidr
        cidr = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False).prefixlen
    else:
        ip = ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False)
        total_hosts = ip.num_addresses

        if total_hosts >= 2 ** 16:
            return "Class A"
        elif total_hosts >= 2 ** 8:
            return "Class B"
        else:
            return "Class C"


def ip_class_private_public(ip_address):
    """Is it a Private Address or Public Address? That's what this function answers"""
    try:
        ip = ipaddress.IPv4Address(ip_address)
    except ipaddress.AddressValueError:
        return error("Error: Invalid Address")
    else:
        first_octet = int(str(ip).split(".")[0])
        if first_octet >= 1 and first_octet <= 126:
            ip_class = "A"
        elif first_octet <= 191:
            ip_class = "B"
        elif first_octet <= 223:
            ip_class = "C"
        elif first_octet >= 224 and first_octet <= 239:
            ip_class = "D"
        else:
            ip_class = "E"
        if ip.is_private:
            return successful(f"According to first octet: Class {ip_class}, Private")
        else:
            return successful(f"According to first octet: Class {ip_class}, Public")


def display_all_info(ip_address, subnet_mask_or_cidr):
    try:
        subnet_mask = int(subnet_mask_or_cidr)
        cidr = subnet_mask_or_cidr
    except ValueError:
        subnet_mask = subnet_mask_or_cidr
        cidr = ipaddress.IPv4Network(f"{ip_address}/{subnet_mask}", strict=False).prefixlen

    ip_int = int(ipaddress.IPv4Address(ip_address))
    ip_hex = hex(ip_int)

    network = ipaddress.IPv4Network(f"{ip_address}/{cidr}", strict=False)
    total_hosts = network.num_addresses
    usable_hosts = total_hosts - 2
    first_address, last_address = list(network.hosts())[0], list(network.hosts())[-1]
    wildcard_mask = ipaddress.IPv4Address((~int(network.netmask)) & 0xFFFFFFFF)
    reverse_dns = reverse_dns_lookup(ip_address)

    table_data = [
        ["IP Address", ip_address],
        ["Subnet Mask", str(network.netmask)],
        ["CIDR Notation", str(cidr)],
        ["Network Address", str(network.network_address)],
        ["Broadcast Address", str(network.broadcast_address)],
        ["Network Address with CIDR Notation", str(network)],
        ["Possible Number of Subnets", str(2 ** (32 - int(cidr)))],
        ["Total Number of Hosts", str(total_hosts)],
        ["Number of Usable Hosts", str(usable_hosts)],
        ["IP class and private/public", ip_class_private_public(ip_address)],
        ["Binary Version of IP", ip_to_binary(ip_address)],
        ["Binary Subnet Mask", str(network.netmask)],
        ["Usable Host IP Range", f"{first_address} - {last_address}"],
        ["Integer ID", str(ip_int)],
        ["Hex ID", str(ip_hex)],
        ["Reverse DNS Lookup", reverse_dns]
    ]

    print(tabulate(table_data, headers=["Category", "Value"], tablefmt="grid"))


def subnetting_calculator(ip_range, num_subnets):
    try:
        network = ipaddress.IPv4Network(ip_range, strict=False)
        subnets = list(network.subnets(new_prefix=num_subnets))
        table_data = [["Subnet", "Network Address"]]
        for subnet in subnets:
            table_data.append([f"/{subnet.prefixlen}", str(subnet.network_address)])
        print(tabulate(table_data, headers="firstrow", tablefmt="grid"))
    except ipaddress.AddressValueError:
        return error("Error: Invalid IP range or number of subnets")


def reverse_dns_lookup(ip_address):
    try:
        domain_name = socket.gethostbyaddr(ip_address)[0]
        return successful(domain_name)
    except (socket.herror, socket.gaierror):
        return error("Reverse DNS lookup failed")


def identify_ip_address_type(ip_address):
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            return successful("Private IP Address")
        elif ip.is_loopback:
            return successful("Loopback IP Address")
        elif ip.is_multicast:
            return successful("Multicast IP Address")
        else:
            return successful("Public IP Address")
    except ValueError:
        return error("Invalid IP Address")


def main_menu():
    print("\n==== Modern IP Tool ====")
    print("Choose an option:")
    print("1. Binary IP to Dotted Decimal Notation IP address")
    print("2. IP address to Binary")
    print("3. Find Network Address from IP and Subnet Mask")
    print("4. Find Network Address from IP/CIDR notation")
    print("5. Calculate Possible Subnetting from IP range")
    print("6. Determine IP Class and Private/Public Status")
    print("7. Display All Information for an IP Address and Subnet")
    print("8. Subnetting Calculator")
    print("9. Reverse DNS Lookup")
    print("10. Identify IP Address Type")
    print("11. Exit")
    print("========================")


def run_tool():
    running = True
    while running:
        main_menu()
        try:
            choice = int(input("Enter the option number: "))
        except ValueError:
            print(error("Error: Use the options provided"))
        except (KeyboardInterrupt, EOFError):
            sys.exit(error("Exited"))
        else:
            try:
                if choice == 1:
                    # Binary to IP
                    binary_ip = input("Enter the binary IP address: ")
                    print(binary_to_ip(binary_ip))
                elif choice == 2:
                    # IP to binary
                    ip_address = input("Enter the IP address: ")
                    print(ip_to_binary(ip_address))
                elif choice == 3:
                    # network address from IP and Subnet Mask
                    ip_address = input("Enter the IP address: ")
                    subnet_mask = input("Enter the subnet mask: ")
                    print(network_address(ip_address, subnet_mask))
                elif choice == 4:
                    # network address from IP/CIDR
                    ip_address = input("Enter the IP address/CIDR: ")
                    print(cidr_to_subnet_mask(ip_address))
                elif choice == 5:
                    # possible number of subnets
                    ip_address = input("Enter the IP network: ")
                    subnet_mask = input("Enter the subnet mask or CIDR: ")
                    print(possible_number_of_subnets(ip_address, subnet_mask))
                elif choice == 6:
                    # is it a private or public IP address?
                    ip_address = input("Enter the IP address: ")
                    print(ip_class_private_public(ip_address))
                elif choice == 7:
                    # get a nice consolidated view of the IP address
                    ip_address = input("Enter the IP address: ")
                    subnet_mask_or_cidr = input("Enter the subnet mask or CIDR notation: ")
                    display_all_info(ip_address, subnet_mask_or_cidr)
                elif choice == 8:
                    # subnetting calculator
                    ip_range = input("Enter the IP range: ")
                    num_subnets = int(input("Enter the number of subnets: "))
                    subnetting_calculator(ip_range, num_subnets)
                elif choice == 9:
                    # reverse DNS lookup
                    ip_address = input("Enter the IP address: ")
                    print(reverse_dns_lookup(ip_address))
                elif choice == 10:
                    # identify IP address type
                    ip_address = input("Enter the IP address: ")
                    print(identify_ip_address_type(ip_address))
                elif choice == 11:
                    # exit
                    sys.exit(successful('Exiting...'))
                else:
                    # input validation
                    print(error('Invalid option. Please try again.'))

            except (KeyboardInterrupt, EOFError):
                sys.exit(error("Exited"))


if __name__ == "__main__":
    run_tool()
