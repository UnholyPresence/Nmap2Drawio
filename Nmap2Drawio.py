########################################################################
#~Welcome to Unholy's Nmap2Drawio~
#
# ---/!\ THIS IS A WORK IN PROGRESS /!\ ---
# This is an active project, and I'll be updating it soon!
#
# The goal of this project is for you, the Analyst, Pentester, or Red
# Teamer to be able to run an  nmap -oX scan of whatever flavor you wish
# and have this script automatically generate you a graphic network map
# ready for you to toss into a report. There are other tools out there
# that do the same thing, but I plan to have this script be a module in
# a broader, customizable report-generation automation that takes
# general and expected artifacts that you might discover over the course
# of an engagement, and turn it into (most of) your report for you.
#
# _-^-_MOAR HACKING. LESS WRITING._-^-_
#   |                               |
########################################################################

#Imports
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field


#Define a class to hold ports/services/states/versions
@dataclass
class NmapPort:
	number: int
	protocol: str
	state: str
	service: str = ""
	product: str = ""
	version: str = ""

#Define a class to hold host information
@dataclass
class NmapHost:
	ip: str
	status: str = "unknown"
	hostnames: list[str] = field(default_factory=list)
	mac: str = ""
	vendor: str = ""
	ports: list[NmapPort] = field(default_factory=list)

#Define a class to hold the whole scan
@dataclass
class NmapScan:
	source_file: str
	hosts: list[NmapHost] = field(default_factory=list)

#Test Main
#def main():
#	ssh_port = NmapPort(
#		number=22,
#		protocol="tcp",
#		state="open",
#		service="ssh",
#		product="OpenSSH",
#		version="22.2"
#	)
#	test_host = NmapHost(
#		ip="127.0.0.1",
#		status="up",
#		hostnames=["127.0.0.1"],
#		mac="00:00:00:00:00:00",
#		vendor="Dell",
#		ports=[ssh_port]
#	)
#	scan = NmapScan(
#		source_file="manual-test",
#		hosts=[test_host]
#	)
#	print(scan)
#
#if __name__ == "__main__":
#	main()

def parse_nmap_xml(path: str) -> NmapScan:
	tree = ET.parse(path)
	root = tree.getroot()

	scan = NmapScan(source_file=path)

	print(root.tag)

	for host_elem in root.findall("host"):
		status = "unknown"
		ip = ""
		mac = ""
		vendor = ""

		hostnames = []
		ports = []

		hostnames_elem = host_elem.find("hostnames")
		if hostnames_elem is not None:
			for hostname_elem in hostnames_elem.findall("hostname"):
				name = hostname_elem.get("name", "")
				if name:
					hostnames.append(name)

		ports = []

		ports_elem = host_elem.find("ports")
		if ports_elem is not None:
			for port_elem in ports_elem.findall("port"):
				protocol = port_elem.get("protocol", "")
				number = int(port_elem.get("portid", 0))

				state = ""
				service = ""
				product = ""
				version = ""

				state_elem = port_elem.find("state")
				if state_elem is not None:
					state = state_elem.get("state", "")

				service_elem = port_elem.find("service")
				if service_elem is not None:
					service = service_elem.get("name", "")
					product = service_elem.get("product", "")
					version = service_elem.get("version", "")

				port = NmapPort(
					number=number,
					protocol=protocol,
					state=state,
					service=service,
					product=product,
					version=version
				)

				ports.append(port)

		print(host_elem.tag)

		for address_elem in host_elem.findall("address"):
			if address_elem.get("addrtype") == "ipv4":
				ip = address_elem.get("addr", "")
			if address_elem.get("addrtype") == "mac":
				mac = address_elem.get("addr", "")
				vendor = address_elem.get("vendor", "")

		status_elem = host_elem.find("status")
		if status_elem is not None:
			status = status_elem.get("state", "unknown")

		host = NmapHost(
			ip=ip,
			status=status,
			mac=mac,
			vendor=vendor,
			hostnames=hostnames,
			ports=ports
		)

		scan.hosts.append(host)

	return scan

def main():
	scan = parse_nmap_xml("SampleXMLs/xmltest.xml")
	print(scan)

if __name__ == "__main__":
	main()
