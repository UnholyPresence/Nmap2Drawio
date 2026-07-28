# Nmap2Drawio

Turn an `nmap -oX` scan straight into a [draw.io](https://app.diagrams.net) network diagram.

Point it at a directory full of Nmap XML output and it'll parse every host, its
open ports/services, and its MAC/vendor info, then lay it out as a diagram —
gateway at the top, discovered hosts arranged in a grid below — ready to drop
into a pentest or red team report.

> **Work in progress.** The layout logic is intentionally simple right now
> (one gateway, everything else in rows of three). Expect it to grow into a
> module for a larger report-generation toolkit.

## Requirements

- Python 3.10+ (uses `list[str]` / `X | None` type hints)
- No third-party dependencies — everything is standard library
  (`xml.etree.ElementTree`, `dataclasses`, `pathlib`)

## Usage

Run an Nmap scan with XML output:

```bash
nmap -oX scan.xml <target>
```

Then run the script from the same directory as your `.xml` file(s):

```bash
python3 Nmap2Drawio.py
```

- If one or more `*.xml` files are found in the current directory, each is
  parsed and turned into a `<filename>.drawio` file next to it.
- If none are found, you'll be prompted for a directory to search instead.
- A summary of discovered hosts and open ports is printed to the console as
  each file is processed.

Open the resulting `.drawio` file in [draw.io](https://app.diagrams.net) (or
the desktop/VS Code app) to view and edit the diagram.

### Diagram layout

- A host is treated as the **gateway** if its IP ends in `.1`, and is placed
  at the top of the diagram.
- Every other discovered host is placed in a grid below, connected to the
  gateway with a line.
- Each host box shows its hostname/IP, vendor, MAC address, and open
  ports/services.
- Only hosts with `state="up"` ports marked `open` are included — closed and
  filtered ports are skipped.

## Project layout

```
Nmap2Drawio.py        # main tool: parse XML -> generate .drawio diagram
NmapXMLParserOnly.py  # standalone parser (no diagram generation), useful
                       # for quick summaries or as a lighter-weight import
SampleXMLs/            # example Nmap XML scan for testing
Outputs/               # generated .drawio files land here
```

## Sample data

`SampleXMLs/xmltest.xml` is included so you can try the tool without running
a real scan:

```bash
python3 Nmap2Drawio.py
# No XMLs in this dir. Run Nmap2Drawio in the dir where your files are or specify target directory:
SampleXMLs
```

(or `cd SampleXMLs && python3 ../Nmap2Drawio.py` to run it from that
directory directly, so it's picked up automatically)

## Roadmap

- Smarter layout for larger/segmented networks (subnets, multiple gateways)
- Configurable styling (colors, grouping by OS/vendor/service)
- Planned as a module in a broader automated report-generation pipeline

## License

MIT — see [LICENSE](LICENSE). Free to use and modify; if you base your own
code on this, please keep the attribution.
