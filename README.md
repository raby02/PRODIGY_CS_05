# PRODIGY_CS_05

# Network Packet Analyzer

## Description

This project is a simple network packet analyzer developed using Python and the Scapy library. The tool captures and analyzes network packets, displaying relevant information such as source and destination IP addresses, protocols, and payload data. It is designed for educational purposes to help understand network traffic and packet structures.

**Note:** Ensure ethical use of this tool and obtain explicit permission before capturing network traffic on any network.

## Features

- Captures and analyzes network packets.
- Displays source and destination IP addresses.
- Identifies and displays protocols (TCP, UDP, and others).
- Shows the first 100 bytes of the packet payload in hexadecimal format.

## Requirements

- Python 3.x
- Scapy library

## Installation

1. **Clone the repository:**

    ```sh
    git clone https://github.com/raby02/PRODIGY_CS_05.git
    cd PRODIGY_CS_05
    ```

2. **Install the required Python packages:**

    ```sh
    pip install scapy
    ```

## Usage

You can run the Network Packet Analyzer from the command line. The tool accepts the following options:

- `-c` or `--count`: Number of packets to capture (default: 10).
- `-i` or `--interface`: Network interface to use. If not specified, the default network interface will be used.

## Code Explanation

The script uses `scapy` to sniff network packets and extract relevant information. Here’s a breakdown of the code:

### `packet_callback(packet)`

This function is called for each captured packet. It performs the following:

- **Checks if the packet contains an IP layer**: 
    ```python
    if IP in packet:
    ```
- **Extracts and prints the source and destination IP addresses**: 
    ```python
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    ```
- **Identifies the protocol and prints it**:
    ```python
    protocol = packet[IP].proto
    if protocol == 6:  # TCP
    elif protocol == 17:  # UDP
    else:
    ```
- **For TCP packets, prints the source and destination ports**:
    ```python
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    ```
- **For UDP packets, prints the source and destination ports**:
    ```python
    if UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    ```
- **Displays the first 100 bytes of the packet payload in hexadecimal format**:
    ```python
    print("Payload (first 100 bytes):", packet[IP].payload.hexdump()[:100])
    ```

### `main()`

This function sets up command-line argument parsing and starts the packet capture process:

- **Sets up command-line argument parsing using `argparse`**:
    ```python
    parser = argparse.ArgumentParser(description="Simple Network Packet Analyzer")
    parser.add_argument("-c", "--count", type=int, default=10, help="Number of packets to capture (default: 10)")
    parser.add_argument("-i", "--interface", default=None, help="Network interface to use")
    args = parser.parse_args()
    ```
- **Starts the packet capture process**:
    ```python
    print("Starting packet capture...")
    print(f"Capturing {args.count} packets on interface {args.interface or 'default'}")
    sniff(prn=packet_callback, count=args.count, iface=args.interface)
    ```

The `sniff` function from `scapy` is used to capture packets. The `prn` parameter specifies the callback function (`packet_callback`) that is called for each captured packet.

## Ethical Use

This tool is intended for educational purposes only. Unauthorized packet capturing and network sniffing can be illegal and unethical. Always obtain proper authorization before capturing network traffic on any network.

Using this tool responsibly helps ensure that it serves as a valuable learning resource while respecting privacy and legal boundaries.

### Example

To capture 20 packets on the default network interface, use the following command:

```sh
python packet_analyzer.py -c 20
```

To capture 15 packets on a specific network interface (e.g., eth0), use this command:

```sh
python packet_analyzer.py -c 15 -i eth0
```

