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

def parse_nmap_xml(path: str) -> NmapScan:
	tree = ET.parse(path)
	root = tree.getroot()

	scan = NmapScan(source_file=path)

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

	x = 40
	width = 280
	horizontal_gap = 320
	vertical_gap = 40
	hosts_per_row = 3

	gateway_x = 360
	gateway_y = 40
	gateway_width = 280

	# A dedicated lane just past the last column, never crossed by any row's
	# boxes, so the trunk line can run through it at any depth without
	# passing through a host.
	trunk_x = x + (hosts_per_row * horizontal_gap)

	if gateway is not None:
		gateway_id = str(cell_id)
		gateway_height = calculate_host_cell_height(gateway)
		add_host_cell(root, gateway_id, gateway, gateway_x, gateway_y, gateway_width, gateway_height)
		host_cell_ids[gateway.ip] = gateway_id
		gateway_bottom = gateway_y + gateway_height
		cell_id += 1
		y = gateway_bottom + vertical_gap
	else:
		gateway_id = None
		gateway_bottom = None
		y = gateway_y

	other_hosts = [host for host in scan.hosts if gateway is None or host.ip != gateway.ip]

	rows = [other_hosts[i:i + hosts_per_row] for i in range(0, len(other_hosts), hosts_per_row)]

	# Column 0 is always populated, so the spine's left end is the same for
	# every row regardless of how many hosts fill out the rest of it.
	left_center_x = x + (width / 2)

	last_mid_y = None
	row_index = 0

	for row_hosts in rows:
		row_height = max(calculate_host_cell_height(host) for host in row_hosts)
		row_top = y
		mid_y = row_top - (vertical_gap / 2)
		last_mid_y = mid_y

		if gateway_id is not None:
			add_line_cell(root, f"spine_{row_index}", SPINE_STYLE, trunk_x, mid_y, left_center_x, mid_y)

		for column, host in enumerate(row_hosts):
			current_id = str(cell_id)

			host_x = x + (column * horizontal_gap)
			host_y = row_top

			height = calculate_host_cell_height(host)
			add_host_cell(root, current_id, host, host_x, host_y, width, height)

			host_cell_ids[host.ip] = current_id

			if gateway_id is not None:
				host_center_x = host_x + (width / 2)
				add_drop_cell(root, f"drop_{current_id}", DROP_STYLE, host_center_x, mid_y, current_id)

			cell_id += 1

		y = row_top + row_height + vertical_gap
		row_index += 1

	if gateway_id is not None and last_mid_y is not None:
		add_line_cell(root, "trunk", TRUNK_STYLE, trunk_x, gateway_bottom, trunk_x, last_mid_y)

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

# Descending thicknesses make it obvious at a glance which tier of the
# trunk/spine/drop hierarchy a given line segment belongs to.
TRUNK_STYLE = "endArrow=none;html=1;rounded=0;curved=0;strokeWidth=5;"
SPINE_STYLE = "endArrow=none;html=1;rounded=0;curved=0;strokeWidth=3;"
DROP_STYLE = "endArrow=none;html=1;rounded=0;curved=0;strokeWidth=2;entryX=0.5;entryY=0;entryDx=0;entryDy=0;"

def add_line_cell(root, cell_id: str, style: str, x1: float, y1: float, x2: float, y2: float) -> None:
	"""A standalone straight segment (trunk or spine) not attached to any vertex."""
	edge = ET.SubElement(root, "mxCell", {
		"id": cell_id,
		"value": "",
		"style": style,
		"edge": "1",
		"parent": "1"
	})

	geometry = ET.SubElement(edge, "mxGeometry", {
		"relative": "1",
		"as": "geometry"
	})

	ET.SubElement(geometry, "mxPoint", {"x": str(x1), "y": str(y1), "as": "sourcePoint"})
	ET.SubElement(geometry, "mxPoint", {"x": str(x2), "y": str(y2), "as": "targetPoint"})

def add_drop_cell(root, cell_id: str, style: str, x: float, y: float, target_id: str) -> None:
	"""A short segment from a fixed spine point down into a host's top edge."""
	edge = ET.SubElement(root, "mxCell", {
		"id": cell_id,
		"value": "",
		"style": style,
		"edge": "1",
		"parent": "1",
		"target": target_id
	})

	geometry = ET.SubElement(edge, "mxGeometry", {
		"relative": "1",
		"as": "geometry"
	})

	ET.SubElement(geometry, "mxPoint", {"x": str(x), "y": str(y), "as": "sourcePoint"})

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

if __name__ == "__main__":
	main()