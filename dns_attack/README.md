# DNS Redirect Tool

The DNS Redirect Tool is a Python script that allows you to redirect DNS responses to a specified IP address. It utilizes the Scapy library to intercept and modify DNS packets.

## Prerequisites

- Python 3.x
- Scapy library (`pip install scapy`)
- netfilterqueue library (`pip install NetfilterQueue`)

## Usage

To use the DNS Redirect Tool, follow the steps below:

1. Install the required libraries mentioned in the prerequisites section.

2. Save the code in a Python file (e.g., `dns_attack.py`).

3. Open a terminal or command prompt and navigate to the directory containing the script.

4. Run the script using the following command:

   ```
   python3 dns_attack.py <interface> [-v] [-vd <victim_domain>] [-r <redirected_ip>]
   ```

   - `<interface>` (mandatory): The network interface to capture and modify DNS packets on.
   - `-v` or `--verbose` (optional): Enable verbose mode to display additional information during the execution.
   - `-vd <victim_domain>` (optional): Specify a victim domain to target for DNS redirection. If not provided, all DNS responses will be redirected.
   - `-r <redirected_ip>` (optional): The IP address to redirect DNS responses to.

5. Once the tool is running, it will intercept DNS packets and modify the responses accordingly.

   - If a victim domain is specified, only DNS responses containing that domain will be redirected.
   - If no victim domain is specified, all DNS responses will be redirected.

   The modified DNS responses will have the IP address field replaced with the specified redirected IP address.

6. To stop the tool, press `Ctrl+C` in the terminal or command prompt.

## Examples

1. Redirect all DNS responses to a specific IP address:

   ```
   python3 dns_attack.py eth0 -r 192.168.1.100
   ```

   This command will intercept DNS responses on the `eth0` interface and redirect them to the IP address `192.168.1.100`.

2. Redirect DNS responses for a specific domain to a different IP address:

   ```
   python3 dns_attack.py wlan0 -r 10.0.0.99 -vd example.com
   ```

   This command will intercept DNS responses on the `wlan0` interface and redirect only the responses containing the domain `example.com` to the IP address `10.0.0.99`.

3. Redirect DNS responses with verbose output:

   ```
   python3 dns_attack.py eth1 -r 172.16.0.50 -v
   ```

   This command will intercept DNS responses on the `eth1` interface and redirect them to the IP address `172.16.0.50`, displaying verbose output during the execution.

## Important Notes

- Ensure that the script is executed with root or administrator privileges, as it requires access to network interfaces and iptables rules.

- The script modifies DNS responses by manipulating packets at the network layer. Use this tool responsibly and in compliance with applicable laws and regulations.

- Before running the script, make sure you understand the potential impact of DNS redirection and use it only in controlled environments for authorized testing or educational purposes.

- It is recommended to familiarize yourself with the Scapy library and the netfilterqueue library for a better understanding of the underlying packet manipulation and interception techniques.

## Disclaimer

The DNS Redirect Tool is provided as-is without any warranties or guarantees. Use it at your own risk. The authors of this tool shall not be held responsible for