import sys
import pcap
import dpkt
import socket

class Viewer:
	"""Observes IPv4 ICMP packet traffic on a network or in a file"""

	def __init__(self, interface, packet_cnt):
		"""Initializes viewer"""

		self.interface = interface
		self.packet_cnt = packet_cnt
		self.sniffer = pcap.pcap(name=interface, snaplen=65535, promisc=True, timeout_ms=10000, immediate=False)
		self.sniffer.setfilter("icmp and ip")

	def sniff(self):
		"""Runs viewer"""

		echo = "viewer: listening on {}".format(self.interface)
		print(echo)

		self.sniffer.loop(self.packet_cnt, Viewer.handlepkt)

	@staticmethod
	def handlepkt(timestamp, packet):
		"""Callback for pcap loop"""

		Viewer.printICMP(timestamp, packet)

	@staticmethod
	def printICMP(timestamp, packet):
		"""Echoes ICMP data"""

		echo = str(timestamp)

		eth = dpkt.ethernet.Ethernet(packet)

		if not isinstance(eth.data, dpkt.ip.IP):
			print("Unsupported packet type")

		else:
			ip = eth.data

			if isinstance(ip.data, dpkt.icmp.ICMP):
				icmp = ip.data

				if icmp.type == 0 or icmp.type == 8:
					ip_src = Viewer.ip_to_str(ip.src)
					ip_dst = Viewer.ip_to_str(ip.dst)
					i_type = Viewer.icmp_type(icmp.type)
					i_id = Viewer.parse_id(repr(icmp.data))
					i_seq = Viewer.parse_seq(repr(icmp.data))
					i_len = Viewer.parse_len(repr(icmp.data))

					echo += " {} > {}: {}, id {}, seq {}, ".format(ip_src, ip_dst, i_type, i_id, i_seq)
					echo += "length {}".format(i_len)
					print(echo)

	@staticmethod
	def ip_to_str(inet):
    		"""Stringify IPv4 or IPv6 address"""

    		try:
        		return socket.inet_ntop(socket.AF_INET, inet)

    		except ValueError:
        		return socket.inet_ntop(socket.AF_INET6, inet)

	@staticmethod
	def icmp_type(i_type):
		"""Translates from ICMP type to ICMP echo message"""

		types = {0 : "ICMP echo reply", 8 : "ICMP echo request"}

		return types[i_type]

	@staticmethod
	def parse_id(dstr):
		"""Retreives id from ICMP message"""

		id_ind = dstr.find("id")

		if id_ind != -1:
			c_id = dstr.find(",", id_ind)

			return dstr[id_ind + 3 : c_id]

		else:
			return 256

	@staticmethod
	def parse_seq(dstr):
		"""Retreives seq from ICMP message"""

		seq_ind = dstr.find("seq")
		c_id = dstr.find(",", seq_ind)

		return dstr[seq_ind + 4 : c_id]

	@staticmethod
	def parse_len(dstr):
		"""Retreives len from ICMP message"""

		len_ind = dstr.find("data")
		c_id = dstr.find(")", len_ind)

		msg = dstr[len_ind + 6 : c_id - 1]

		msg_ind = msg.find("\\x0b")

		if msg_ind == -1:
			return len(msg)

		else:
			return len(msg[:msg_ind])

	@staticmethod
	def printUsageInstr():
		"""Displays viewer command line parameters upon error"""

		print("Viewer Usage Instructions")
		print("-" * 60)
		print("viewer -i interface -c N -r filename")
		print("where")
		print("-i, --int listen on the specified interface")
		print("-c, --count print count number of packets and quit")
		print("-r, --read read the pcap file and print packets")

def main():
	req_args = 3

	if len(sys.argv) < req_args:
		Viewer.printUsageInstr()
		quit()

	if len(sys.argv) == 3:
		pfilename = sys.argv[2]
		pfile = open(pfilename, "rb")
		pfpcap = dpkt.pcap.Reader(pfile)

		for timestamp, buf in pfpcap:
			Viewer.printICMP(timestamp, buf)

	else:
		interface = sys.argv[2]
		packet_cnt = int(sys.argv[4])

		viewer = Viewer(interface, packet_cnt)
		viewer.sniff()

if __name__ == "__main__":
	main()

