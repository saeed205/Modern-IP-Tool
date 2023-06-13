# Modern IP Tool

The Modern IP Tool is a command-line utility that provides various IP address-related functions and calculations. It offers features like converting between binary and decimal IP addresses, finding network addresses, subnetting calculations, reverse DNS lookup, and identifying IP address types. This tool is built using Python and leverages the `ipaddress` and `tabulate` libraries.

![Features](https://github.com/saeed205/Modern-IP-Tool/blob/main/01.png)

## Features

- Binary IP to Dotted Decimal Notation IP address conversion
- IP address to binary conversion
- Finding network addresses from IP and subnet mask
- Finding network addresses from IP/CIDR notation
- Calculating possible subnetting from an IP range
- Determining IP class and private/public status
- Displaying comprehensive information for an IP address and subnet
- Subnetting calculator
- Reverse DNS lookup
- Identifying IP address types (public, private, loopback, multicast)

## Installation

1. Clone this repository or download the source code.
2. Install the required dependencies by running `pip install -r requirements.txt`.

## Usage

To run the Modern IP Tool, execute the `main.py` script in the command-line interface.

```shell
python main.py
```

The tool will present a menu with numbered options. Enter the corresponding option number to perform the desired IP-related operation.

### Examples

1. Binary IP to Dotted Decimal Notation IP address:
   - Input: `11000000101010000000000100000001`
   - Output: `Decimal IP: 192.168.1.1`

2. IP address to binary:
   - Input: `192.168.1.1`
   - Output: `Binary IP: 11000000101010000000000100000001`

3. Find Network Address from IP and Subnet Mask:
   - Input:
     - IP address: `192.168.1.10`
     - Subnet mask: `255.255.255.0`
   - Output: `Network address with CIDR Notation: 192.168.1.0/24`

4. Find Network Address from IP/CIDR notation:
   - Input: `192.168.1.0/24`
   - Output:
     - Network address: `192.168.1.0`
     - IP Subnet Mask: `255.255.255.0`

5. Calculate Possible Subnetting from IP range:
   - Input:
     - IP network: `192.168.0.0`
     - Subnet mask or CIDR: `16`
   - Output: `Possible Number of Subnets: 256`

6. Determine IP Class and Private/Public Status:
   - Input: `192.168.1.10`
   - Output: `According to first octet: Class C, Private`

7. Display All Information for an IP Address and Subnet:
   - Input:
     - IP address: `192.168.1.10`
     - Subnet mask or CIDR notation: `24`
   - Output: Displays a comprehensive table with information such as network address, broadcast address, total number of hosts, etc.
   
![Display All](https://github.com/saeed205/Modern-IP-Tool/blob/main/02.png)


8. Subnetting Calculator:
   - Input:
     - IP range: `192.168.0.0/16`
     - Number of subnets: `4`
   - Output: Displays a table with subnet information, including network addresses for each subnet.

9. Reverse DNS Lookup:
   - Input: `8.8.8.8`
   - Output: Reverse DNS lookup result for the given IP address.

10. Identify IP Address Type

:
    - Input: `192.168.1.10`
    - Output: `Private IP Address`

11. Exit: Exits the Modern IP Tool.

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.
