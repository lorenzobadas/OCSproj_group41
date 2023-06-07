# ARP Spoofing Tool

The ARP Spoofing Tool is a Python script that enables ARP spoofing attacks on a local network. It utilizes the Scapy library to construct and send ARP packets, allowing the attacker to manipulate the ARP tables of target devices.

## Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)

## Usage

To use the ARP Spoofing Tool, follow the steps below:

1. Install the required libraries mentioned in the prerequisites section.

2. Save the code in a Python file (e.g., `arp_spoofing_tool.py`).

3. Open a terminal or command prompt and navigate to the directory containing the script.

4. Run the script using the following command:

   ```
   python arp_spoofing_tool.py [-m] [-v] [-t <ip1> <ip2>] <interface>
   ```

   - `-m` or `--mitm` (optional): Enable Man-in-the-Middle (MITM) attack mode. When enabled, the script performs ARP spoofing between the two specified target IP addresses.
   - `-v` or `--verbose` (optional): Enable verbose mode to display additional information during the execution.
   - `-t <ip1> <ip2>` (optional): Specify two target IP addresses directly instead of scanning the network for devices.
   - `<interface>` (mandatory): The network interface to perform the ARP spoofing attack on.

5. If the `-t` option is not used, the script will perform a network scan to discover devices on the local network. You will be prompted to choose two victims from the scanned devices.

6. Once the victims are selected, the script will either perform a spoofing attack or a MITM attack based on the options provided.

   - In the spoofing attack mode, the script spoofs the ARP tables of the two victims, redirecting their network traffic to the attacker's machine.
   - In the MITM attack mode, the script performs ARP spoofing between the two victims, allowing the attacker to intercept and manipulate their network traffic.

7. To stop the ARP spoofing attack, press `Ctrl+C` in the terminal or command prompt.

## Examples

1. Perform a spoofing attack between two target IP addresses:

   ```
   python arp_spoofing_tool.py -v -t 192.168.1.100 192.168.1.200 eth0
   ```

   This command will perform an ARP spoofing attack between the IP addresses `192.168.1.100` and `192.168.1.200` on the `eth0` interface, displaying verbose output during the execution.

2. Perform a MITM attack by scanning the network and selecting victims:

   ```
   python arp_spoofing_tool.py -m wlan0
   ```

   This command will perform a network scan on the `wlan0` interface, display the list of scanned devices, and prompt you to choose two victims for the MITM attack.

## Important Notes

- Ensure that the script is executed with root or administrator privileges, as ARP spoofing requires low-level network access.

- The script utilizes ARP spoofing, which is a malicious technique. Use this tool responsibly and only in controlled environments with proper authorization.

- Be aware of the legal implications and potential consequences of performing ARP spoofing attacks without proper authorization. Make sure to comply with applicable laws and regulations.

- It is recommended to familiarize yourself with ARP (Address Resolution Protocol) and the Scapy library to gain a better understanding of the underlying mechanisms and techniques employed by the script.

## Disclaimer

The ARP Spoofing Tool is provided as-is without any warranties or guarantees. Use it at your own risk. The authors of this tool shall not be held responsible for any damages or misuse of the tool.