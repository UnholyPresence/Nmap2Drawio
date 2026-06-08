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
from pathlib import Path


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

#	Debug Print
#	print(root.tag)

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
				if state != "open":
					continue

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

#		Debug Print
#		print(host_elem.tag)

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

def print_scan_summary(scan: NmapScan) -> None:
	print(f"Scan source: {scan.source_file}")
	print(f"Hosts Discovered: {len(scan.hosts)}")
	print()

	for host in scan.hosts:
		hostname_text = ""
		if host.hostnames:
			hostname_text = (f" ({', '.join(host.hostnames)})")

		vendor_text = ""
		if host.vendor:
			vendor_text = f" {host.vendor}"

		mac_text = ""
		if host.mac:
			mac_text = f" {host.mac}"

		print(f"{host.ip}{hostname_text} [{host.status}]{vendor_text}{mac_text}")

		if host.ports:
			for port in host.ports:
				print(f" {port.number}/{port.protocol} {port.state} {port.service}")
		else:
			print(f" No open ports discovered")

		print()

def find_the_xmls() -> list[Path]:
	xml_paths = list(Path(".").glob("*.xml"))

	if xml_paths:
		return xml_paths

	target_dir = input("No XMLs in this dir. Run Nmap2Drawio in the dir where your files are or specifiy target directory: ")
	target_path = Path(target_dir)

	if not target_path.exists() or not target_path.is_dir():
		print("***IMPOSSIBLY LOUD WRONG BUZZER*** Not a valid directory")
		return[]

	xml_paths = list(target_path.glob("*.xml"))

	if not xml_paths:
		print("No XMLs in here")
		return[]

	return xml_paths

def main():
	xml_path = find_the_xmls()
	if not xml_path:
		return

	for xmlpath in xml_path:
		scan = parse_nmap_xml(str(xmlpath))
		print_scan_summary(scan)

if __name__ == "__main__":
	main()
