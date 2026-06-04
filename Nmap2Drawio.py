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
def main():
	ssh_port = NmapPort(
		number=22,
		protocol="tcp",
		state="open",
		service="ssh",
		product="OpenSSH",
		version="22.2"
	)
	test_host = NmapHost(
		ip="127.0.0.1",
		status="up",
		hostnames=["127.0.0.1"],
		mac="00:00:00:00:00:00",
		vendor="Dell",
		ports=[ssh_port]
	)
	scan = NmapScan(
		source_file="manual-test",
		hosts=[test_host]
	)
	print(scan)

if __name__ == "__main__":
	main()

