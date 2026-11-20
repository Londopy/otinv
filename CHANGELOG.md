# Changelog

All notable changes to otinv are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The section for a version is
what appears on its GitHub release page. Validated in CI by
[patchnotes](https://github.com/Londopy/patchnotes).

## [Unreleased]

## [0.2.0] - 2026-11-19

### Added

- Device identity from BACnet (I-Am and device properties, including location), S7comm component identification, OPC UA server descriptions, Omron FINS controller data, ROC Plus system configuration and C37.118 configuration frames, from zeek logs and from Malcolm exports.
- Packet numbers for evidence: when otinv runs zeek on a capture, it matches each evidence line to its packet, and the appendix shows the frame number Wireshark uses. Reads pcap and pcapng.
- `evidence.csv` lists the log lines behind every finding (up to 10,000 each, from 25 before), with packet numbers and a Wireshark filter for each. The appendix still shows the first 25 per finding.
- Shared copies withhold names, locations and other text that devices announce about themselves; makes, models and firmware stay.
- `[details]` in site.toml records each device's location, drawings, configuration backup and programming tools, which CISA's CPG 2.0 asks for. They go into new `inventory.csv` columns and are withheld from shared copies.
- A `configured_from` inventory column: the computers seen sending a device programming or configuration traffic.
- The Capture workflow now runs zeek natively on Linux and inside WSL on Windows as well as in Docker, and checks otinv against 15 public ICS captures from CISA's ICSNPP and zeek's test suites.
- A volunteer guide (`docs/volunteer-guide.md`), with how to keep captures encrypted, and a research paper draft (`docs/paper-draft.md`).

### Changed

- New `inventory.csv` columns are added at the end; existing columns keep their order.
- The capture test is marked ignored instead of passing silently when zeek isn't there.

### Fixed

- The WSL runner passes long paths, so captures and temp folders under 8.3 short names (`C:\Users\RUNNER~1`) open inside WSL.

## [0.1.1] - 2026-11-19

### Added

- Malcolm exports as input: the zeek documents from Malcolm's `/mapi/document` API, saved as JSON or NDJSON, give the same report as the logs, with warnings for incomplete or overlapping pages.
- Releases install, check and uninstall the setup.exe and MSIs on a Windows runner before they're published.

### Fixed

- Modbus device identification read the firmware version only under the spec's object name; ICSNPP calls it `MajorMinorVersion`.

## [0.1.0] - 2026-11-19

### Added

- Zeek log reader for TSV and JSON logs that reads only the logs and fields it uses, drops user names and passwords while reading, and skips lines cut off mid-write.
- Asset inventory from passive traffic: IP, MAC (wire or DHCP), vendor, host name, first and last seen, with router MACs detected and left out.
- Role inference (controller, HMI/SCADA, engineering workstation, network service, IT host), with the log line behind each role.
- Device identity from EtherNet/IP List Identity and Modbus Device Identification logs.
- Findings with evidence: industrial protocols to or from the internet, remote access on control-system computers, readable logins, unexpected Modbus writes and DNP3 control, new devices, control-system devices using the internet.
- One-page plain-English summary, HTML and text appendix, inventory CSV, communication map (SVG, Graphviz, Mermaid, CSV).
- Diff mode against a previous run, saved as a `.londopy` file.
- `--pseudonymize` writes a pseudonymized copy of the reports to `share/`. Every shared file is checked for IP and MAC addresses before otinv finishes.
- Running Zeek on a capture through a native install, WSL or a local Docker image (with `--network none`). Raw Zeek logs go to a temporary folder unless `--keep-logs` is given.
- Editable rules (`otinv rules`) and site files (`otinv site-template`).
- `otinv update` checks GitHub for a newer release and, once you say yes, downloads it, checks its SHA-256 against the release's `SHA256SUMS.txt` and replaces the running exe. `--check` only reports. It is the only command that uses the network, and only when you run it.
- Windows downloads: a per-user installer with an opt-in "Add otinv to the PATH" task, MSIs for x64, x86 and arm64 that put otinv on PATH, standalone portable exes, a portable zip, and `install.ps1`/`install.cmd` script installs.
- Linux x86_64 downloads: a `.tar.gz` with the binary, LICENSE and README, and the bare binary.
- Pseudonym aliases stay the same from one run to the next: the `pseudonym-map.csv` next to `--previous` (or `--pseudonym-map`) is reused.
- Input limits: lines over 1 MiB are skipped and counted, and a log over `--max-log-mb` (default 4096) is refused.
- Findings name the CISA CPG 2.0 goals they relate to.
- A Capture workflow that runs otinv through real Zeek and the ICSNPP parsers on a generated lab capture.
- Every release lists all its files in `SHA256SUMS.txt` and offers each download as a web-seeded torrent and magnet link.

[Unreleased]: https://github.com/Londopy/otinv/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Londopy/otinv/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Londopy/otinv/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Londopy/otinv/releases/tag/v0.1.0
