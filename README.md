# otinv

[![CI](https://github.com/Londopy/otinv/actions/workflows/ci.yml/badge.svg)](https://github.com/Londopy/otinv/actions/workflows/ci.yml)
[![changelog](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Londopy/otinv/gh-pages/changelog-badge.json)](CHANGELOG.md)
[![License](https://img.shields.io/github/license/Londopy/otinv)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org)
[![Platforms](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-0078D6)](#building-from-source)

**Turn a capture from a small utility's control network into an asset inventory and a one-page "what to fix first" report that an operator can actually read.**

Small water and power utilities usually have the free monitoring tools: Zeek,
CISA's ICSNPP parsers, Malcolm. What they're missing is the expert who turns
that output into an inventory an inspector will accept and a short list of
fixes. otinv reads Zeek's logs and does that part. It runs offline on a laptop
and only listens. It never sends a packet to the network it describes.

```text
$ otinv analyze capture-2026-11.pcap -o otinv-2026-11 --previous otinv-2026-10/run.londopy
9 devices found, 9 problems (3 critical, 4 high, 2 medium).
Start with otinv-2026-11/summary.txt

WHAT TO FIX FIRST
  1. [CRITICAL] Remote-control software can reach control-system computers
     Operator screen (HMI/SCADA) 10.10.2.20 accepts VNC connections from
     internet address 203.0.113.50 and Engineering workstation 10.10.2.30.
     Do this: Turn off remote-access services nobody uses. For the ones you
     need, require a VPN and multi-factor login, ...
```

## Features

- **Asset inventory** (`inventory.csv`): IP, MAC, vendor, role, make/model, firmware and serial when the device announces them, protocols, first and last seen. One row per device.
- **Role inference**: controllers (PLC/RTU), operator screens (HMI/SCADA), engineering workstations, network services and IT hosts. Each role comes with the log line that justifies it.
- **Plain-English findings**, each listing the exact Zeek log lines behind it:
  - industrial protocols to or from the internet
  - remote-access services (VNC, RDP, TeamViewer, telnet...) on control-system computers or reachable from the internet, and remote-control tools dialing out from them
  - logins sent as readable text (telnet, FTP, plain web logins). otinv flags them but throws the user names and passwords away while reading the logs.
  - Modbus writes or DNP3 control from a computer that doesn't normally send them
  - control-system devices using ordinary internet services
  - new devices since the last run
- **One-page summary** (`summary.txt`): the top five fixes, ranked, in words a two-person utility can act on.
- **Appendix** (`appendix.html`, `appendix.txt`): every finding with evidence, the full inventory, and a communication map drawn in the page. No scripts, fonts or network needed.
- **Communication map** as Graphviz (`comms.dot`), Mermaid (`comms.mmd`) and CSV (`comms.csv`).
- **Diff mode**: "since last month". New, missing and changed devices (MAC swaps, firmware changes), plus new and resolved problems.
- **Pseudonymized copy** for sharing with a reviewer, in its own `share/` folder: addresses, MACs, names and serials become `host-01`, `ext-01`, ... Before it finishes, otinv scans every shared file for IP and MAC addresses. If it finds one, it deletes the share folder and stops.
- **Deterministic and tunable**: the same logs always give the same report. Every protocol, threshold and sentence lives in a rules file you can edit.

## Install

**Windows:** download `otinv-<version>-setup-x64.exe` from the
[latest release](https://github.com/Londopy/otinv/releases/latest) and run
it. It installs for your user only, so there's no admin prompt. Tick **Add
otinv to the PATH** to run `otinv` from any terminal. The release also has:

- MSIs for x64, x86 and arm64. They install per-user by default and put
  otinv on the PATH. For a machine-wide install:
  `msiexec /i otinv-<version>-x64.msi ALLUSERS=2 MSIINSTALLPERUSER=""`.
- Standalone portable exes, and a zip with all three builds.
- A PowerShell script that picks the right build, checks it and installs it
  (`-AddToPath` also puts it on your PATH):

```powershell
& ([scriptblock]::Create((irm https://github.com/Londopy/otinv/releases/latest/download/install.ps1))) -AddToPath
```

**Linux (x86_64):** built on Ubuntu 22.04, so it needs glibc 2.35 or newer.

```sh
tar xzf otinv-v<version>-linux-x86_64.tar.gz
install -Dm755 otinv-v<version>-linux-x86_64/otinv ~/.local/bin/otinv
```

The binaries aren't code-signed, so SmartScreen may warn (**More info**,
then **Run anyway**). Each release lists every file's SHA-256 in
`SHA256SUMS.txt`; check your download against it.

### Updating

`otinv update` checks GitHub for a newer release and asks before installing
it. It checks the download against the release's `SHA256SUMS.txt`, then
replaces the running exe. `otinv update --check` only says whether there is
a newer release. It never runs on its own. For an all-users install in
Program Files, it prints the link to the new MSI or setup.exe instead.

otinv itself is one self-contained binary. To analyze **captures** (rather
than Zeek logs you already have), it also needs Zeek with CISA's ICSNPP
packages, which it finds on its own:

| Where | Setup |
|---|---|
| Linux | Install [Zeek](https://zeek.org), then `zkg install icsnpp-modbus icsnpp-dnp3 icsnpp-enip ...` |
| Windows | The same inside WSL (`wsl -e zeek --version` should work) |
| Either | `docker build -t otinv-zeek:local docker/zeek-icsnpp` (Zeek 9.0.1 and CISA's ICSNPP parsers; the Capture workflow builds this exact image and checks otinv against it) |

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

The **Capture** workflow (`.github/workflows/capture.yml`) builds the
Docker image and generates a lab capture with
`tests/fixtures/make_lab_pcap.py`. It runs otinv on that capture through
real Zeek and ICSNPP, and checks every expected finding. The native and WSL
runners use the same Zeek command, but no test runs them.

## Usage

```sh
# a capture: otinv runs zeek offline, then analyzes the logs it wrote
otinv analyze capture.pcap -o otinv-2026-11

# logs you already have (from zeek, Malcolm, or a sensor)
otinv analyze /path/to/zeek/logs -o otinv-2026-11

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

Use a new output folder for every run. Re-running into the same folder
clears otinv's own old files first, so a stale diff or shared copy never sits
next to new reports. The report folder is **sensitive**: it maps a utility's
control network and its weak spots. Every folder includes a
`README-SENSITIVE.txt` that says what may be shared and what may not. In
short: only `share/`, and never `run.londopy` or `pseudonym-map.csv`.

Logs can be Zeek's default tab-separated format or JSON. otinv reads only
`conn.log` (required), `modbus.log`, `dnp3.log`, `ftp.log`, `http.log`,
`dhcp.log`, and the ICSNPP identity logs (`cip_identity.log`,
`modbus_read_device_identification.log`). It keeps only the fields it uses
and drops everything else as it reads, including URLs, cookies, SNMP
communities and FTP reply text. User names and passwords leave only a "a
login happened" marker. Other logs in the folder aren't read. A file not named after its type, like `2026-11-01-conn.log`, is recognized from the `#path` or `_path` in its first lines.
Compressed logs are skipped with a warning, and lines cut off mid-write (or
longer than 1 MiB) are skipped and counted. A single log over 4 GB is refused
unless you raise `--max-log-mb`.

For MAC addresses in `conn.log`, run Zeek with
`policy/protocols/conn/mac-logging`. otinv does that itself when it runs
Zeek.

## Configuration

Two optional files:

- **`--site site.toml`**: facts about one utility. Friendly names for devices, address ranges that are yours besides the private ones, and the computers that are allowed to send control commands. Get a template with `otinv site-template > site.toml`.
- **`--rules rules.toml`**: protocols, role hints and every finding's text and severity. Start from the built-in rules with `otinv rules > rules.toml`. Your file replaces the built-in one.

```toml
# site.toml
name = "Example Water District"
local_networks = ["203.0.113.0/28"]     # public addresses used inside the plant
expected_writers = ["10.0.2.20"]        # the SCADA server

[names]
"10.0.1.10" = "Well 2 PLC"
"10.0.2.20" = "Control room HMI"
```

`--oui oui.csv` adds the full IEEE vendor list (download it once from
https://standards-oui.ieee.org/oui/oui.csv). Without it, otinv uses a small
built-in list of vendors common on control networks.

### Inventory columns

`inventory.csv` is the "regularly updated inventory of all organizational
assets" of CISA's CPG 2.0 goal **2.A Manage Organizational Assets**. It uses
the vocabulary of CISA's asset-inventory guidance (role, OT or IT,
make/model, firmware, network address, communications), so you can hand it
to an inspector or insurer as it is. The communication map (`comms.*`, and
the map in the appendix) covers goal **2.E Document Network Topology**. Every
finding names the CPG 2.0 goals it relates to.

| Column | Meaning |
|---|---|
| `ip_address`, `name` | Address, and the friendly name from site.toml |
| `role`, `ot_or_it` | Inferred role; OT for controllers, HMIs and engineering workstations |
| `mac_address`, `mac_vendor` | MAC from the wire or DHCP, and its maker. Left empty when the MAC belongs to a router |
| `hostname` | From DHCP |
| `make_model`, `firmware_revision`, `serial_number`, `device_type` | What the device announced about itself (EtherNet/IP List Identity, Modbus Device Identification) |
| `protocols_served`, `protocols_used` | Protocols it answered, and protocols it started |
| `talks_with` | Number of distinct devices it exchanged traffic with |
| `first_seen_utc`, `last_seen_utc` | Within the capture |
| `open_findings` | Rule ids of findings about this device |
| `role_basis` | Why it got its role |

## What it will not do

- **Scan anything, ever.** It reads logs of traffic that already happened.
- Be an IDS or a sensor. Malcolm, Zeek and Dragos already do that well.
- Upload anything. There's no telemetry, and no network access except `otinv update`, which only runs when you type it and only talks to GitHub.
- Touch or fix devices. It tells a person what to do.
- See devices that stayed silent during the capture, or traffic that never crossed the mirror port.

## How is this different from...?

| | otinv | Malcolm / Zeek alone | GRASSMARLIN |
|---|---|---|---|
| Reads passive captures | ✅ (via Zeek) | ✅ | ✅ |
| Plain-English findings for non-experts | ✅ | ❌ | ❌ |
| Inventory CSV in CISA's vocabulary | ✅ | ❌ | ❌ |
| Month-to-month diff | ✅ | ❌ | ❌ |
| Runs on a laptop with nothing else installed (from logs) | ✅ | ❌ | ✅ |
| Maintained | ✅ | ✅ | ❌ (archived) |

otinv sits on top of Zeek and ICSNPP. It doesn't replace them.

## How it works

```text
capture --(zeek -r, ICSNPP, mac-logging)--> zeek logs --> reader (drops credentials)
        --> inventory + roles + comms map --> rules --> findings
        --> summary / appendix / CSV / map / run.londopy
```

- An address becomes a device only if it sent something, so probes to empty addresses don't invent devices.
- A MAC seen with several addresses is treated as a router's, and assigned to none of them.
- "Expected" control commands come from the site file's `expected_writers`. Without that list, a computer counts as expected if it polled the same controller at least `min_polls` times. Only requests count, so a Modbus transaction logged as a REQ and a RESP line counts once, and a refused write still counts as an attempt. A host that writes without polling that controller regularly is flagged. If it doesn't poll anything regularly, it's labelled "Other computer", not HMI.
- A MAC seen with internet traffic is also treated as a router's.
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

The test fixtures are synthetic Zeek logs of a small lab network, a clean
hour and a bad one, written by `tests/fixtures/make_fixtures.py`.

## Layout

```text
src/
  main.rs        command line
  zeek.rs        zeek log reader (TSV + JSON); credential fields are dropped here
  analyze.rs     inventory, roles, communication map
  checks.rs      the findings
  config.rs      rules.toml and site.toml
  model.rs       the run: assets, edges, findings (saved in run.londopy)
  diff.rs        run-to-run changes
  pseudo.rs      aliases for sharing
  report/        summary and appendix (text, HTML), CSV, map (DOT, Mermaid, SVG)
  runner.rs      running zeek: native, WSL or Docker
  londopy.rs     .londopy files
  update.rs      otinv update: GitHub Releases check, SHA-256, exe swap
rules/default.toml   the built-in rules
installer/           Inno Setup and WiX sources, install.ps1 and install.cmd
scripts/release_notes.py   the release page, checksums and torrents
docker/zeek-icsnpp/  Zeek + ICSNPP image for the docker runner
tests/               scenario, edge-case and capture tests; lab fixtures and
                     the generators for its logs and its capture
```

## Contributing

Issues and pull requests are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
**Never attach real utility captures or reports to an issue.** Reproduce the
problem with the lab fixtures, or with a capture you made yourself.

## License

MIT — see [LICENSE](LICENSE).
