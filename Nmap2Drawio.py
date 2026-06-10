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

def gen_blank_drawio(output_path: str) -> None:
	mxfile = ET.Element("mxfile", {"host": "app.diagrams.net"})
	diagram = ET.SubElement(mxfile, "diagram", {"name": "Nmap2Drawio"})
	model = ET.SubElement(diagram, "mxGraphModel")
	root = ET.SubElement(model, "root")
	ET.SubElement(root, "mxCell", {"id": "0"})
	ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

	tree = ET.ElementTree(mxfile)
	tree.write(output_path, encoding="utf-8", xml_declaration=True)

def get_host_display_name(host: NmapHost) -> str:
	if host.hostnames:
		return host.hostnames[0]

	if host.ip:
		return host.ip

	return "Unknown Host"

def build_host_label(host: NmapHost) -> str:
	lines = []

	display_name = get_host_display_name(host)
	lines.append(display_name)

	if host.hostnames and host.ip:
		lines.append(host.ip)

	if host.vendor:
		lines.append(host.vendor)

	if host.mac:
		lines.append(host.mac)

	if host.ports:
		lines.append("")
		for port in host.ports:
			lines.append(f"{port.number}/{port.protocol} {port.service}")

	return "\n".join(lines)

def find_default_gateway(scan: NmapScan) -> NmapHost | None:
	for host in scan.hosts:
		if host.ip.endswith(".1"):
			return host

	return None

def calculate_host_cell_height(host: NmapHost) -> int:
	line_count = len(build_host_label(host).splitlines())
	line_height = 18
	padding = 40
	minimum_height = 100

	return max(minimum_height, padding + (line_count * line_height))

#def main():
#	xml_path = find_the_xmls()
#	if not xml_path:
#		return
#
#	for xmlpath in xml_path:
#		scan = parse_nmap_xml(str(xmlpath))
#		print_scan_summary(scan)
#
#if __name__ == "__main__":
#	main()

def generate_drawio(scan: NmapScan, output_path: str) -> None:
	mxfile = ET.Element("mxfile", {"host": "app.diagrams.net"})
	diagram = ET.SubElement(mxfile, "diagram", {"name": "Nmap2Drawio"})
	model = ET.SubElement(diagram, "mxGraphModel")
	root = ET.SubElement(model, "root")

	ET.SubElement(root, "mxCell", {"id": "0"})
	ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

	gateway = find_default_gateway(scan)

	cell_id = 2
	host_cell_ids = {}

	if gateway is not None:
		gateway_id = str(cell_id)
		gateway_width = 280
		gateway_height = calculate_host_cell_height(gateway)
		add_host_cell(root, gateway_id, gateway, 360, 40, gateway_width, gateway_height)
		host_cell_ids[gateway.ip] = gateway_id
		cell_id += 1
	else:
		gateway_id = None

	x = 40
	width = 280
	y = 260
	horizontal_gap = 320
	vertical_gap = 40
	hosts_per_row = 3
	column = 0

	for host in scan.hosts:
		if gateway is not None and host.ip == gateway.ip:
			continue

		current_id = str(cell_id)

		host_x = x + (column * horizontal_gap)
		host_y = y

		height = calculate_host_cell_height(host)
		add_host_cell(root, current_id, host, host_x, host_y, width, height)

		host_cell_ids[host.ip] = current_id

		if gateway_id is not None:
			edge_id = f"edge_{gateway_id}_{current_id}"
			add_edge_cell(root, edge_id, gateway_id, current_id)

		cell_id += 1
		column += 1

		if column >= hosts_per_row:
			column = 0
			y += height + vertical_gap

	tree = ET.ElementTree(mxfile)
	tree.write(output_path, encoding="utf-8", xml_declaration=True)

def add_host_cell(root, cell_id: str, host: NmapHost, x: int, y: int, width: int, height: int) -> None:
	label = build_host_label(host).replace("\n", "<br>")

	cell = ET.SubElement(root, "mxCell", {
		"id": cell_id,
		"value": label,
		"style": "rounded=1;whiteSpace=wrap;html=1;align=left;verticalAlign=top;spacing=8;fillColor=#dae8fc;strokeColor=#6c8ebf;fontSize=12;",
		"vertex": "1",
		"parent": "1"
	})

	ET.SubElement(cell, "mxGeometry", {
		"x": str(x),
		"y": str(y),
		"width": str(width),
		"height": str(height),
		"as": "geometry"
	})

def add_edge_cell(root, cell_id: str, source_id: str, target_id: str) -> None:
	edge = ET.SubElement(root, "mxCell", {
		"id": cell_id,
		"value": "",
		"style": "endArrow=none;html=1;rounded=0;strokeWidth=2;",
		"edge": "1",
		"parent": "1",
		"source": source_id,
		"target": target_id
	})

	ET.SubElement(edge, "mxGeometry", {
		"relative": "1",
		"as": "geometry"
	})

def main():
	xml_path = find_the_xmls()
	if not xml_path:
		return

	for xmlpath in xml_path:
		scan = parse_nmap_xml(str(xmlpath))
		print_scan_summary(scan)

		output_name = f"{Path(xmlpath).stem}.drawio"
		generate_drawio(scan, output_name)
		print(f"Wrote file to {output_name}")
#	for host in scan.hosts:
#		print("----- HOST LABEL -----")
#		print(build_host_label(host))

#	gen_blank_drawio("nmap_output.drawio")
#	print("Created file in current directory: nmap_output.drawio")

if __name__ == "__main__":
	main()
