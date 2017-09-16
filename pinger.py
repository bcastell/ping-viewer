import sys
import socket
import random
import struct
import time
import select

class Pinger:
	"""Sends periodic ping messages to destination IP address"""

    def __init__(self, payload_str, packet_cnt, destination_ip, timeout = 2):
        """Initializes pinger"""

        self.payload_str = payload_str
        self.packet_cnt = packet_cnt
        self.destination_ip = destination_ip
        self.timeout = timeout
        self.pingsocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

	def ping(self):
        """Pings the destination IP address"""

        echo = "Pinging {} with {} bytes of data \"{}\":".format(self.destination_ip, len(self.payload_str), self.payload_str)
        print(echo)

        ICMP_ECHO_REQUEST = 8

        received = 0
        lost = 0
        minrtt = 0
        maxrtt = 0
        avgrtt = 0
        avgcnt = 0

		for i in range(self.packet_cnt):
			packet_id = int((self.timeout * random.random()) % 65535)
			header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, packet_id, 1)

			if len(self.payload_str) % 2 == 0:
				self.payload_str += "\v"

			csum = self.checksum(header + self.payload_str.encode())
			header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(csum), packet_id, 1)
			packet = header + self.payload_str.encode()
			sent = self.pingsocket.sendto(packet, (self.destination_ip, 1))
			delay, ttl = self.recv_ping(packet_id, time.time())

			if delay == None:
				echo = "  No reply from {}".format(self.destination_ip)
				print(echo)

				lost += 1

			else:
				delay = round(delay * 1000.0, 4)
				fixlen = len(self.payload_str) - 1 if self.payload_str[len(self.payload_str) - 1] == "\v" else len(self.payload_str)

				echo = "  Reply from {}: bytes={} time={}ms TTL={}".format(self.destination_ip, fixlen, delay, ttl)
				print(echo)

				received += 1
				minrtt = delay if minrtt == 0 else min(minrtt, delay)
				maxrtt = delay if maxrtt == 0 else max(maxrtt, delay)
				avgrtt += delay
				avgcnt += 1

		echo = "Ping statistics for {}:".format(self.destination_ip)
		print(echo)

		echo = " Packets: Sent = {}, Received = {}, Lost = {} ({}% loss)".format(self.packet_cnt, received, lost, lost / self.packet_cnt * 100)
		print(echo)

		echo = " Approximate round trip times in milli-seconds:"
		print(echo)

		avgms = avgrtt / avgcnt if avgcnt != 0 else 0

		echo = " Minimum = {}ms, Maximum = {}ms, Average = {}ms".format(minrtt, maxrtt, round(avgms, 4))
		print(echo)

	def checksum(self, data):
		"""Calculates checksum"""

		total = 0
		upper = len(data.decode()) - 1
		lower = 0

		while lower < upper:
			val = ord(data.decode()[lower + 1]) * 256 + ord(data.decode()[lower])
			total += val
			total &= 0xffffffff
			lower += 2

		if upper < len(data.decode()):
			total += ord(data.decode()[len(data.decode()) - 1])
			total &= 0xffffffff

		total = (total >> 16) + (total & 0xffff)
		total = total + (total >> 16)
		check = ~total
		check = check & 0xffff
		check = check >> 8 | (check << 8 & 0xff00)

		return check

	def recv_ping(self, packet_id, time_sent):
		"""Receive a ping"""

		time_left = self.timeout

		while True:
			sselect = time.time()
			ready = select.select([self.pingsocket], [], [], time_left)
			iselect = time.time() - sselect

			if ready[0] == []:
				return None, 0

			time_received = time.time()
			rec_packet, addr = self.pingsocket.recvfrom(1024)

			ip_header = rec_packet[:20]
			iphver, iphtos, iphlen, iphid, iphflags, iphttl, iphpro, iphcheck, iphsrcip, iphdestip = struct.unpack("!BBHHHBBHII", ip_header)

			icmp_header = rec_packet[20:28]
			ptype, code, checksum, p_id, sequence = struct.unpack("bbHHh", icmp_header)

			if p_id == packet_id:
				return time_received - time_sent, iphttl

			time_left -= time_received - time_sent

			if time_left <= 0:
				return None, 0

	def printUsageInstr():
		"""Displays pinger command line parameters upon error"""

		print("Pinger Usage Instructions")
		print("-" * 60)
		print('pinger -p "data" -c N -d IP')
		print("where")
		print("-p, --payload is the string to include in the payload")
		print("-c, --count is the number of packets used to compute RTT")
		print("-d, --dst is the destination IP for the ping message")

	def checkConnection():
		"""Checks if host has steady Internet connection"""

		SERVER = "www.google.com"

		try:
			host = socket.gethostbyname(SERVER)
			s = socket.create_connection((host, 80), 2)

		except:
			echo = "Network is unreachable."
			print(echo)

			quit()

def main():
	req_args = 7

	if len(sys.argv) < req_args:
		Pinger.printUsageInstr()
		quit()

	payload_str = sys.argv[2]
	packet_cnt = int(sys.argv[4])
	destination_ip = sys.argv[6]

	Pinger.checkConnection()

	pinger = Pinger(payload_str, packet_cnt, destination_ip)
	pinger.ping()

if __name__ == "__main__":
	main()

