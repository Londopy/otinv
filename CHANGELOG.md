# Changelog

All notable changes to otinv are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). The section for a version is
what appears on its GitHub release page. Validated in CI by
[patchnotes](https://github.com/Londopy/patchnotes).

## [Unreleased]

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
