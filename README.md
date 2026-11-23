<p align="center">
  <img src="docs/images/icon.png" width="96" height="96" alt="otinv icon: three linked network nodes, one in orange">
</p>

<h1 align="center">otinv</h1>

<p align="center">
  <b>Turn a capture from a small utility's control network into an asset inventory<br>and a one-page "what to fix first" report that an operator can actually read.</b>
</p>

<p align="center">
  <a href="https://github.com/Londopy/otinv/actions/workflows/ci.yml"><img src="https://github.com/Londopy/otinv/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/Londopy/otinv/actions/workflows/capture.yml"><img src="https://github.com/Londopy/otinv/actions/workflows/capture.yml/badge.svg" alt="Capture tests through real Zeek"></a>
  <a href="https://github.com/Londopy/otinv/releases/latest"><img src="https://img.shields.io/github/v/release/Londopy/otinv" alt="Latest release"></a>
  <a href="https://github.com/Londopy/otinv/releases"><img src="https://img.shields.io/github/downloads/Londopy/otinv/total" alt="Downloads"></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Londopy/otinv/gh-pages/changelog-badge.json" alt="Changelog"></a>
  <br>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Londopy/otinv" alt="License"></a>
  <a href="https://www.rust-lang.org"><img src="https://img.shields.io/badge/dynamic/toml?url=https%3A%2F%2Fraw.githubusercontent.com%2FLondopy%2Fotinv%2Fmain%2FCargo.toml&query=%24.package%5B%27rust-version%27%5D&label=rust&prefix=%3E%3D&color=b7410e" alt="Minimum Rust version"></a>
  <a href="#install"><img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-0078D6" alt="Platforms: Windows and Linux"></a>
  <a href="https://zeek.org"><img src="https://img.shields.io/badge/reads-Zeek%20%2B%20ICSNPP-2f6f8f" alt="Reads Zeek and ICSNPP logs"></a>
  <a href="#network-use"><img src="https://img.shields.io/badge/analysis-offline%2C%20passive-2e7d32" alt="Analysis is offline and passive"></a>
  <a href="https://github.com/Londopy/otinv/commits/main"><img src="https://img.shields.io/github/last-commit/Londopy/otinv" alt="Last commit"></a>
</p>

<p align="center">
  <img src="docs/images/demo.gif" width="900" alt="The otinv window: a capture, a site file and last month's run are picked, Analyze runs Zeek in Docker with a progress line, then the Results page lists what to fix first, with critical and high findings outlined in red and orange.">
  <br>
  <sub>The otinv window on the synthetic lab capture from <code>tests/fixtures</code>. No real utility's data appears anywhere in this README.</sub>
</p>

Small water and power utilities usually have the free monitoring tools: Zeek,
CISA's ICSNPP parsers, Malcolm. What they're missing is the expert who turns
that output into an inventory an inspector will accept and a short list of
fixes. otinv reads Zeek's logs and does that part. 🔒 It runs offline on a
laptop and only listens: it never sends a packet to the network it describes.

It comes as two programs that do the same analysis: **otinv-gui**, a window
for people who'd rather not use a terminal, and **otinv**, the command line.

## Quick start

1. Download `otinv-<version>-setup-x64.exe` from the [latest release](https://github.com/Londopy/otinv/releases/latest) and run it. No admin prompt.
2. Open **otinv** from the Start menu.
3. Pick a capture, a folder of Zeek logs or a Malcolm export, and press **Analyze**.

Or from a terminal, on the same synthetic lab capture as the GIF:

```text
$ otinv analyze lab-2026-11.pcap -o otinv-2026-11 --previous otinv-2026-10/run.londopy --site site.toml
8 devices found, 8 problems (3 critical, 4 high, 1 medium).
Start with otinv-2026-11/summary.txt

$ cat otinv-2026-11/summary.txt
...
WHAT TO FIX FIRST
  1. [CRITICAL] Remote-control software can reach control-system computers
     Operator screen (HMI/SCADA) "Control room HMI" (10.10.2.20) accepts VNC
     connections from internet address 203.0.113.50 and Engineering
     workstation "Engineering laptop" (10.10.2.30).
     ...
     Do this: Turn off remote-access services nobody uses. For the ones you
     need, require a VPN and multi-factor login, replace default or shared
     passwords, and allow connections only from known addresses.
```

Analyzing a capture (rather than logs you already have) also needs Zeek; see
[Zeek for captures](#zeek-for-captures).

## What you get

Every run writes one report folder:

| File | What's in it |
|---|---|
| 📋 `summary.txt` | One page: the top five fixes, ranked, in words a two-person utility can act on |
| 🗂️ `inventory.csv` | One row per device: IP, MAC, vendor, role, make/model, firmware, serial, protocols, first and last seen, and who configures it. Ready for CISA's CPG 2.0 goal 2.A |
| 📄 `appendix.html`, `appendix.txt` | Every finding with its evidence, the full inventory, and a communication map drawn in the page. No scripts, fonts or network needed |
| 🔎 `evidence.csv` | The Zeek log lines behind every finding, with a Wireshark filter for each connection (the packet's frame number when otinv ran Zeek itself) |
| 🕸️ `comms.dot`, `comms.mmd`, `comms.csv` | The communication map as Graphviz, Mermaid and CSV (CPG 2.0 goal 2.E) |
| 📈 `diff.txt`, `diff.html` | With `--previous`: new, missing and changed devices (MAC swaps, firmware changes), plus new and resolved problems |
| 🤝 `share/` | With `--pseudonymize`: the same reports with addresses, MACs, names and serials replaced, safe to send to a reviewer |
| 💾 `run.londopy` | The saved run, for next month's comparison |

<p align="center">
  <img src="docs/images/report-map.png" width="900" alt="The communication map in appendix.html: devices in columns for Internet, IT, network services, engineering, HMI/SCADA and PLC/RTU, with arrows from the device that started each conversation and red outlines on devices with findings.">
  <br>
  <sub>The communication map in <code>appendix.html</code>, from the same synthetic lab capture.</sub>
</p>

<details>
<summary><b>More screenshots</b></summary>

<p align="center">
  <img src="docs/images/analyze.png" width="800" alt="The Analyze page with a capture, report folder, site file and last month's run chosen, Zeek found in Docker with ICSNPP, and the pseudonymized copy ticked.">
  <br><sub>Analyze: what to read, which Zeek it found, and where the reports go.</sub>
</p>

<p align="center">
  <img src="docs/images/results.png" width="800" alt="The Results page: 8 devices, 3 critical, 4 high, 1 medium, changes since the previous run, buttons for the full report, the report folder and the copy for sharing, and the first two critical findings.">
  <br><sub>Results: what to fix first, each with "Do this" and "Why it matters".</sub>
</p>

<p align="center">
  <img src="docs/images/inventory.png" width="800" alt="The lower half of the Results page: a high and a medium finding, then the inventory table with address, name, role, make and model, firmware and protocols for eight lab devices.">
  <br><sub>The inventory, with friendly names from the site file.</sub>
</p>

</details>

## What it finds

Each finding names the exact Zeek log lines behind it and the CISA CPG 2.0
goals it relates to:

- 🌐 industrial protocols to or from the internet
- 🖥️ remote-access services (VNC, RDP, TeamViewer, telnet...) on control-system computers or reachable from the internet, and remote-control tools dialing out from them
- 🔑 logins sent as readable text (telnet, FTP, plain web logins). otinv flags them but throws the user names and passwords away while reading the logs.
- ⚡ Modbus writes or DNP3 control from a computer that doesn't normally send them
- 📡 control-system devices using ordinary internet services
- 🆕 new devices since the last run

It also works out what each device is:

- **Roles**: controllers (PLC/RTU), operator screens (HMI/SCADA), engineering workstations, network services and IT hosts, each with the log line that justifies it.
- **Identity** from the traffic: EtherNet/IP List Identity, Modbus Device Identification, BACnet I-Am and device properties, S7comm component identification, OPC UA server descriptions, Omron FINS controller data, ROC Plus system configuration and C37.118 configuration frames.
- **MAC vendors** from IEEE's whole registry (MA-L, MA-M, MA-S and IAB), built in, so lookups work offline.

The same logs always give the same report, and every protocol, threshold and
sentence lives in a rules file you can edit.

## Install

| Download | What it is |
|---|---|
| `otinv-<version>-setup-x64.exe` | **Recommended on Windows.** Installs for your user only, adds **otinv** to the Start menu (it opens the window), and can put `otinv` on the PATH |
| `otinv-<version>-x64.msi` (also x86, arm64) | Per-user by default, with the Start menu entry and PATH. Machine-wide: `msiexec /i otinv-<version>-x64.msi ALLUSERS=2 MSIINSTALLPERUSER=""` |
| `otinv-gui-v<version>-x64-portable.exe`, `otinv-v<version>-x64-portable.exe` (also x86, arm64) | The window and the command line as standalone exes |
| `otinv-v<version>-portable.zip` | Both programs for x64, x86 and arm64 |
| `otinv-v<version>-linux-x86_64.tar.gz` | Both programs for Linux (glibc 2.35 or newer, built on Ubuntu 22.04). Each is also attached on its own |

All of them are on the [latest release](https://github.com/Londopy/otinv/releases/latest).
The binaries aren't code-signed, so SmartScreen may warn (**More info**, then
**Run anyway**). Each release lists every file's SHA-256 in `SHA256SUMS.txt`;
check your download against it.

<details>
<summary><b>Install with PowerShell, or on Linux</b></summary>

A script that picks the right build, checks it and installs it (`-AddToPath`
also puts it on your PATH):

```powershell
& ([scriptblock]::Create((irm https://github.com/Londopy/otinv/releases/latest/download/install.ps1))) -AddToPath
```

Linux (x86_64):

```sh
tar xzf otinv-v<version>-linux-x86_64.tar.gz
install -Dm755 otinv-v<version>-linux-x86_64/otinv ~/.local/bin/otinv
install -Dm755 otinv-v<version>-linux-x86_64/otinv-gui ~/.local/bin/otinv-gui
```

</details>

### Updating

`otinv update` checks GitHub for a newer release and asks before installing
it. It checks the download against the release's `SHA256SUMS.txt`, then
replaces the running exe. `otinv update --check` only says whether there is
a newer release. It never runs on its own. For an all-users install in
Program Files, it prints the link to the new MSI or setup.exe instead. In the
window, **About**, **Check for updates** does the same. Either one updates
both programs when they sit in the same folder.

### Zeek for captures

Each program is one self-contained binary. Logs and Malcolm exports need
nothing else. To analyze **captures**, it also needs Zeek with CISA's ICSNPP
packages, which it finds on its own:

| Where | Setup |
|---|---|
| 🐧 Linux | Install [Zeek](https://zeek.org), then `zkg install icsnpp-modbus icsnpp-dnp3 icsnpp-enip ...` (with `sudo` for a packaged Zeek in `/opt/zeek`) |
| 🪟 Windows | The same inside WSL (`wsl -e zeek --version` should work) |
| 🐳 Either | `docker build -t otinv-zeek:local docker/zeek-icsnpp` (Zeek 9.0.1 and CISA's ICSNPP parsers; the Capture workflow builds this exact image and checks otinv against it) |

otinv never downloads or installs any of this itself. It runs Zeek with the
default scripts, the zkg packages and MAC logging, but not your
`site/local.zeek`, because that file can load log shippers or mail settings.
zkg packages still load, so on a Zeek install that also has data-shipping
packages, use a dedicated install or the Docker image. The Docker runner
starts the container with `--network none`.

Zeek's raw logs go to a private temporary folder and are deleted once otinv
has read them, because they can hold user names, passwords and URLs that
otinv's reports leave out. `--keep-logs` keeps them in `<out>/zeek-logs`
instead.

## The window

Open **otinv** from the Start menu (or run `otinv-gui`). It follows the
system's light or dark setting and has five pages:

| Page | What it does |
|---|---|
| **Analyze** | Choose a capture, a folder of Zeek logs or a Malcolm export (or drop it on the window), a report folder (one is suggested, named for the month), and optionally a site file and last month's `run.londopy`. For a capture it checks which Zeek it can use and says plainly what's missing. The run goes in the background with its current step and time shown, and **Stop** ends it (Zeek too) without writing any reports |
| **Results** | What to fix first, the same list as `summary.txt`, then the inventory. Buttons open the full HTML report, the report folder and the copy for sharing. Any `run.londopy` can be opened here too |
| **Compare months** | Two saved runs in; new and missing devices, changed firmware and new and fixed problems out, with the HTML comparison a click away |
| **Site details** | A form for `site.toml`: the utility's name, its own address ranges, which computers may send control commands, and each device's name, location, drawings, configuration backup and tools. Devices from the last results can be added in one click. Unsaved details are never thrown away without asking, closing the window included |
| **About** | The version, links, and the update check |

The window writes exactly the same report folder as the command line.

## Command line

```sh
# a capture: otinv runs zeek offline, then analyzes the logs it wrote
otinv analyze capture.pcap -o otinv-2026-11

# logs you already have (from zeek or a sensor)
otinv analyze /path/to/zeek/logs -o otinv-2026-11

# an export from Malcolm (see "From Malcolm" below)
otinv analyze malcolm-export/ -o otinv-2026-11

# next month: flag new devices and write diff.txt / diff.html
otinv analyze capture-dec.pcap -o otinv-2026-12 --previous otinv-2026-11/run.londopy

# also write a pseudonymized copy to otinv-2026-11/share/ for a volunteer
# reviewer; send only that share/ folder
otinv analyze capture.pcap -o otinv-2026-11 --pseudonymize

# next month: the same devices keep the same aliases (host-03 stays host-03),
# because the pseudonym-map.csv next to --previous is reused automatically
otinv analyze capture-dec.pcap -o otinv-2026-12 --previous otinv-2026-11/run.londopy --pseudonymize

# compare any two saved runs
otinv diff otinv-2026-10/run.londopy otinv-2026-12/run.londopy -o since-october
```

> [!IMPORTANT]
> The report folder is **sensitive**: it maps a utility's control network and
> its weak spots. Every folder includes a `README-SENSITIVE.txt` that says what
> may be shared. In short: only `share/`, and never `run.londopy` or
> `pseudonym-map.csv`.

Use a new output folder for every run. Re-running into the same folder
clears otinv's own old files first, so a stale diff or shared copy never sits
next to new reports.

The pseudonymized copy in `share/` turns addresses, MACs, names and serials
into `host-01`, `ext-01`, ... Before it finishes, otinv scans every shared
file for IP and MAC addresses. If it finds one, it deletes the share folder
and stops.

<details>
<summary><b>Which logs it reads, and what it drops</b></summary>

Logs can be Zeek's default tab-separated format or JSON. otinv reads only
`conn.log` (required), `modbus.log`, `dnp3.log`, `ftp.log`, `http.log`,
`dhcp.log`, and the ICSNPP identity logs (`cip_identity.log`,
`modbus_read_device_identification.log`, `bacnet_discovery.log`,
`bacnet_property.log`, `s7comm_known_devices.log`,
`opcua_binary_get_endpoints_description.log`,
`opcua_binary_create_session_endpoints.log`, `omron_fins_detail.log`,
`roc_plus_sys_cfg.log`, `synchrophasor_cfg_detail.log`). ICSNPP's other
parsers are left out of identity on purpose:

- BSAP and Genisys logs carry no identity at all.
- GE-SRTP logs only the header of the controller's ID reply, and PROFINET
  IO CM only an RPC object UUID.
- EtherCAT identifies slave chips on a bus with no IP address.
- HART-IP identifies field instruments behind a gateway, which have no
  address of their own.
- C12.22's identification-service log is off by default in ICSNPP, and
  holds the meter's identity only as raw bytes.

For the same reason as HART-IP, a BACnet router that answers for several
devices behind it gets only its own device's identity, never theirs.

otinv keeps only the fields it uses and drops everything else as it reads,
including URLs, cookies, SNMP communities and FTP reply text. User names and
passwords leave only a "a login happened" marker. Other logs in the folder
aren't read. A file not named after its type, like `2026-11-01-conn.log`, is
recognized from the `#path` or `_path` in its first lines. Compressed logs
are skipped with a warning, and lines cut off mid-write (or longer than
1 MiB) are skipped and counted. A single log over 4 GB is refused unless you
raise `--max-log-mb`.

For MAC addresses in `conn.log`, run Zeek with
`policy/protocols/conn/mac-logging`. otinv does that itself when it runs
Zeek.

When otinv ran Zeek on the capture itself, each evidence line about a TCP or
UDP connection also names its packet: a `conn.log` line the connection's
first packet, a protocol log line (Modbus, DNP3, HTTP...) the packet carrying
that message. Findings from a log folder or a Malcolm export cite log lines
only. `evidence.csv` keeps up to 10,000 lines per finding, and the total is
always counted.

</details>

<details>
<summary><b>From Malcolm</b></summary>

Malcolm keeps its zeek logs on disk only briefly, so export the zeek
documents from its search index instead, with Malcolm's document API. Save
each response as a `.json` file in one folder, then point otinv at the folder
(or at a single file):

```sh
curl -sk -u <user> https://<malcolm>/mapi/document \
  -H 'Content-Type: application/json' \
  -d '{"doctype": "network", "from": "2026-11-01", "to": "2026-11-02", "limit": 500,
       "sort": ["firstPacket:asc", "event.id:asc"],
       "filter": {"event.provider": "zeek",
                  "event.dataset": ["conn", "modbus", "dnp3", "ftp", "http", "dhcp",
                                    "cip_identity", "modbus_read_device_identification",
                                    "bacnet_discovery", "bacnet_property", "s7comm_known_devices",
                                    "opcua_binary_get_endpoints_description",
                                    "opcua_binary_create_session_endpoints", "omron_fins_detail",
                                    "roc_plus_sys_cfg", "synchrophasor_cfg_detail"]}}' \
  > malcolm-export/page1.json
```

The API returns at most `limit` documents per call. Add `"offset": 500`,
`1000`, ... for the next pages; keep the sort, so the pages don't overlap or
skip. OpenSearch stops at 10,000 per query, so split a longer time range into
several queries. Documents saved one per line (`.ndjson`) work too. Save the
files as UTF-8: in Windows PowerShell 5, `>` writes UTF-16, which otinv
refuses.

otinv warns when a page says the search timed out or failed on some shards,
when the pages hold fewer documents than Malcolm matched, and when a document
appears in more than one page (it's counted once).

otinv maps Malcolm's field names back to zeek's, so the report is the same
as from the logs. Evidence cites the export file and the document's number
in it (its line in an `.ndjson` file, its position in a page's `results`),
plus the zeek `uid` for finding the record in Malcolm. Only zeek documents
are read; Arkime sessions and Suricata alerts are skipped. Malcolm also files
the login of a web form under the same field as a basic-auth login, so from
an export both show as readable logins. The mapping follows Malcolm 26.10's
Logstash pipeline. It's tested against an export built to that mapping, not
yet against a live Malcolm. Evidence from an export has no packet numbers,
because otinv never sees the capture.

The export holds everything Malcolm indexed, including captured passwords
and full URLs, which otinv drops as it reads. Treat it like the raw logs:
keep it off shared drives and delete it after the run.

</details>

## Configuration

Two optional files:

- **`--site site.toml`**: facts about one utility. Friendly names for devices, address ranges that are yours besides the private ones, and the computers that are allowed to send control commands. Get a template with `otinv site-template > site.toml`, or fill in **Site details** in the window.
- **`--rules rules.toml`**: protocols, role hints and every finding's text and severity. Start from the built-in rules with `otinv rules > rules.toml`. Your file replaces the built-in one.

```toml
# site.toml
name = "Example Water District"
local_networks = ["203.0.113.0/28"]     # public addresses used inside the plant
expected_writers = ["10.0.2.20"]        # the SCADA server

[names]
"10.0.1.10" = "Well 2 PLC"
"10.0.2.20" = "Control room HMI"

# what no capture shows; goes into inventory.csv every month
[details."10.0.1.10"]
location = "Well 2 pump house, panel 3"
drawings = "P&ID W2-004 rev C"
config_backup = "program exported 2026-10-03, office file server"
tools = "CLICK Programming Software 3.60"
```

The built-in IEEE vendor list is as of the release; `--oui oui.csv` reads a
newer IEEE file (https://standards-oui.ieee.org/oui/oui.csv, or
`mam.csv`/`oui36.csv`) on top of it. A few vendors common on control
networks get shorter names.

<details>
<summary><b>Inventory columns</b></summary>

`inventory.csv` is the "regularly updated inventory of all organizational
assets" of CISA's CPG 2.0 goal **2.A Manage Organizational Assets**. It uses
the vocabulary of CISA's asset-inventory guidance (role, OT or IT,
make/model, firmware, network address, communications), so you can hand it
to an inspector or insurer as it is. The communication map (`comms.*`, and
the map in the appendix) covers goal **2.E Document Network Topology**.

| Column | Meaning |
|---|---|
| `ip_address`, `name` | Address, and the friendly name from site.toml |
| `role`, `ot_or_it` | Inferred role; OT for controllers, HMIs and engineering workstations |
| `mac_address`, `mac_vendor` | MAC from the wire or DHCP, and its maker. Left empty when the MAC belongs to a router |
| `hostname` | From DHCP |
| `make_model`, `firmware_revision`, `serial_number`, `device_type` | What the device announced about itself (see [What it finds](#what-it-finds)). Other announced facts, like a BACnet device's location or an OPC UA server's product URI, are in the appendix |
| `protocols_served`, `protocols_used` | Protocols it answered, and protocols it started |
| `talks_with` | Number of distinct devices it exchanged traffic with |
| `first_seen_utc`, `last_seen_utc` | Within the capture |
| `open_findings` | Rule ids of findings about this device |
| `role_basis` | Why it got its role |
| `location`, `drawings`, `config_backup`, `tools` | From `[details]` in site.toml: where it is, the drawings it's on, where its configuration is backed up, and the software that programs it. CPG 2.0 asks for these for OT assets, and no capture shows them |
| `configured_from` | Computers seen sending it programming functions (Modbus or DNP3 engineering functions, engineering protocols) or opening management sessions to it (web, SSH, telnet, FTP) |

</details>

## What it will and won't do

| ✅ It does | ❌ It never |
|---|---|
| Read logs of traffic that already happened | Scans anything, ever |
| Run Zeek offline on a capture you give it | Acts as an IDS or a sensor (Malcolm, Zeek and Dragos already do that well) |
| Tell a person what to fix, and why | Touches or fixes devices |
| Check GitHub for an update when you ask | Uploads anything. There's no telemetry |

It can't see devices that stayed silent during the capture, or traffic that
never crossed the mirror port.

## Network use

The analysis never touches a network: `otinv analyze` and `otinv diff` read
files and write files, the window does the same, and the Docker runner
starts Zeek with `--network none`. The one thing that goes online is the
update check, `otinv update` or **Check for updates** in the window, and
only when you ask for it. It asks GitHub's API for the latest release, and if
you say yes, downloads that release's exe and `SHA256SUMS.txt` from GitHub.
It sends nothing about you or your data, and `otinv update --check` only
asks. On a laptop that must stay offline, don't run it; download new
releases on another machine instead.

## Encryption

otinv doesn't encrypt its output, on purpose. By the time it runs, the
capture is already on the same disk unencrypted, and the reports are only as
safe as the capture next to them. Full-disk encryption (BitLocker, LUKS) or
an encrypted container protects all of it at once, and a utility can't be
locked out of its own inventory by a password only otinv knew. The
[volunteer guide](docs/volunteer-guide.md#keeping-the-data-safe) says how to
set it up. What otinv does itself: Zeek's raw logs go to a private temporary
folder and are deleted once read, every report folder carries
`README-SENSITIVE.txt`, and only the pseudonymized `share/` copy is meant to
leave the laptop.

## How is this different from...?

| | otinv | Malcolm / Zeek alone | GRASSMARLIN |
|---|:---:|:---:|:---:|
| Reads passive captures | ✅ (via Zeek) | ✅ | ✅ |
| Plain-English findings for non-experts | ✅ | ❌ | ❌ |
| Inventory CSV in CISA's vocabulary | ✅ | ❌ | ❌ |
| Month-to-month diff | ✅ | ❌ | ❌ |
| Runs on a laptop with nothing else installed (from logs) | ✅ | ❌ | ✅ |
| Maintained | ✅ | ✅ | ❌ (archived) |

otinv sits on top of Zeek and ICSNPP. It doesn't replace them.

## How it works

```mermaid
flowchart LR
    cap[capture] -->|zeek -r, ICSNPP, mac-logging| logs[zeek logs]
    mal[Malcolm export] --> reader
    logs --> reader["reader<br>(drops credentials)"]
    reader --> inv["inventory, roles,<br>comms map"]
    inv --> rules[rules] --> findings[findings]
    findings --> out["summary, appendix, CSV,<br>map, run.londopy"]
```

- An address becomes a device only if it sent something, so probes to empty addresses don't invent devices.
- A MAC seen with several addresses is treated as a router's, and assigned to none of them. So is a MAC seen with internet traffic.
- "Expected" control commands come from the site file's `expected_writers`. Without that list, a computer counts as expected if it polled the same controller at least `min_polls` times. Only requests count, so a Modbus transaction logged as a REQ and a RESP line counts once, and a refused write still counts as an attempt. A host that writes without polling that controller regularly is flagged. If it doesn't poll anything regularly, it's labelled "Other computer", not HMI.
- Function names in the rules are the ones Zeek writes (`OPEN_FILE`, `PROGRAM_UNITY`...). Check them against your Zeek version if you customize the rules.
- Device-supplied text (host names, model strings) is escaped in HTML, and a CSV cell that starts like a spreadsheet formula gets a leading `'`, so it opens as text.
- Each run is saved as `run.londopy`, the shared Londopy file format: a zip holding `londopy.toml` and `run.json`. `--previous` and `otinv diff` read these files.

## Building from source

```sh
git clone https://github.com/Londopy/otinv
cd otinv
cargo build --release
cargo test --all
```

That builds both programs. `cargo build --release --no-default-features`
builds only the command line, without the GUI's dependencies. On Linux the
window needs a desktop session (X11 or Wayland); the command line doesn't.

## Testing

`cargo test` runs everything that needs no Zeek. The test fixtures are
synthetic Zeek logs of a small lab network, a clean hour and a bad one,
written by `tests/fixtures/make_fixtures.py`.

Two tests need Zeek and show as ignored in a plain `cargo test`:

- `tests/capture.rs` writes the lab's bad hour as packets and runs it
  through Zeek. `OTINV_CAPTURE_RUNNER` picks the runner (`docker`, the
  default, `native` or `wsl`).
- `tests/public_traces.rs` runs otinv on public ICS captures listed with
  their hashes in `tests/public-traces.txt`: CISA's ICSNPP test captures
  (BSD-3-Clause) and Zeek's own Modbus and DNP3 test captures, fetched at
  pinned commits. They cover BACnet, S7comm, OPC UA, Omron FINS, ROC Plus,
  C37.118, HART-IP, C12.22, EtherNet/IP, Modbus and DNP3, in pcap and
  pcapng.

```sh
docker build -t otinv-zeek:local docker/zeek-icsnpp
cargo test --test capture -- --ignored
python scripts/fetch_public_traces.py target/public-traces
OTINV_PUBLIC_TRACES=target/public-traces cargo test --test public_traces -- --ignored
```

The **Capture** workflow (`.github/workflows/capture.yml`) runs otinv
through real Zeek all three ways: the Docker image with ICSNPP, Zeek from
the project's Ubuntu packages on PATH, and the same Zeek inside WSL on a
Windows runner. Each run analyzes the lab capture and checks every expected
finding. The Docker run also checks the 15 public ICS captures.

## What hasn't been tested yet

Everything above runs on synthetic captures and public test captures. Still
to do, and none of it can be done from code:

- [ ] a capture off a mirror port on real PLCs (the planned OpenPLC and
  AutomationDirect CLICK lab)
- [ ] an export from a live Malcolm
- [ ] a study of whether operators can act on the one-page report, which
  needs IRB approval
- [ ] feedback from inspectors and insurers on which inventory columns they
  want
- [ ] a pilot at a utility, only through a partner program and with written
  authorization

## Docs

- 📘 [docs/volunteer-guide.md](docs/volunteer-guide.md): running otinv at a
  utility, from the authorization letter to keeping the data safe
- 📝 [docs/paper-draft.md](docs/paper-draft.md): the research write-up

<details>
<summary><b>Layout</b></summary>

```text
src/
  main.rs        command line
  bin/otinv-gui/ the window (egui): one file per page
  command.rs     analyze and diff, shared by both programs
  zeek.rs        zeek log reader (TSV + JSON); credential fields are dropped here
  analyze.rs     inventory, roles, communication map
  checks.rs      the findings
  config.rs      rules.toml and site.toml
  model.rs       the run: assets, edges, findings (saved in run.londopy)
  diff.rs        run-to-run changes
  pseudo.rs      aliases for sharing
  report/        summary and appendix (text, HTML), CSV, map (DOT, Mermaid, SVG)
  runner.rs      running zeek: native, WSL or Docker
  pcap.rs        packet numbers for evidence, read from the capture
  londopy.rs     .londopy files
  update.rs      the update check: GitHub Releases, SHA-256, exe swap
rules/default.toml   the built-in rules
installer/           Inno Setup and WiX sources, install.ps1 and install.cmd
scripts/release_notes.py   the release page, checksums and torrents
scripts/fetch_public_traces.py   downloads the public test captures
scripts/update_oui.py   rebuilds the built-in MAC vendor list
data/oui.tsv         the IEEE MAC vendor registry otinv builds in
assets/              the icon (scripts/make_icon.py draws it)
docs/                volunteer guide, paper draft, README images
docker/zeek-icsnpp/  Zeek + ICSNPP image for the docker runner
tests/               scenario, edge-case, capture and public-capture tests;
                     lab fixtures and the generators for its logs and capture
```

</details>

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).

> [!WARNING]
> **Never attach real utility captures or reports to an issue.** Reproduce the
> problem with the lab fixtures, or with a capture you made yourself.

## License

MIT: see [LICENSE](LICENSE).
