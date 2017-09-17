<h1 align="center">
  <br>
  <span>
    <img src="title.png">
  </span>
</h1>

## Overview
This repository provides tools for sending, receiving, and logging packets. Consisting of a ping utility and packet sniffer, these tools serve to observe network traffic.

### Ping
The ping utility sends ICMP Echo Request packets to a specified IP address and listens for ICMP Echo Reply packets.

#### Report
Pinging a host generates several statistics.
- Packets
  - Sent
  - Received
  - Lost
- RTT
  - Minimum
  - Maximum
  - Average

### Sniffer
The packet sniffer intercepts and analyzes IPv4 ICMP packets on a network or pcap file.

#### Report
Each packet has the following data extracted.
- Timestamp
- Source IP address
- Destination IP address
- Packet Type
- Packet ID
- Sequence Number
- Payload Length

## Usage
To run the ping utility and packet sniffer on macOS and Linux machines, follow these instructions.

### Clone
Clone the remote repository.
```
git clone https://github.com/bcastell/ping-viewer
```

### Navigation
Enter the root directory of the local repository.
```
cd location/where/repository/is/saved/ping-viewer
```

### Dependencies

#### Python
Download the latest version of Python 2 and Python 3.

#### Modules
Install the pypcap and dpkt modules.

pypcap - https://github.com/pynetwork/pypcap
dpkt - https://github.com/kbandla/dpkt

### Execution

#### Ping
To run the ping tool, enter the following command with custom arguments.

```
sudo python3 pinger.py -p data -c 4 -d 206.190.36.45
```

-p: payload string
<br>
-c: number of packets to send
<br>
-d: destination IP address

#### Sniffer

##### Network Interface
To run the packet sniffer to listen on a network interface, enter the following command with custom arguments.

```
sudo python viewer.py -i eth0 -c 10
```

-i: network interface
<br>
-c: number of packets to capture

##### PCAP File
To run the packet sniffer to analyze a pcap file, enter the following command with custom arguments.

```
sudo python viewer.py -r icmp.pcap
```

-r: pcap file

## Authors
* **Brandon Castellanos** - [GitHub](https://github.com/bcastell)

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
