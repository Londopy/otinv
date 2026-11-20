# Plain-language security reporting for non-expert utility operators

Draft, November 2026. Author: Londopy.

This is a working draft of the paper the project plan calls for. The system
and the lab evaluation are done; the user study is designed but not run, and
needs IRB approval first. Numbers here come from the tests in this
repository and can be rerun from it.

## Abstract

Small drinking-water and power utilities can get free network monitoring
(Zeek, CISA's ICSNPP parsers, Malcolm), but turning its output into an
asset inventory and a short list of fixes still takes an expert they don't
have. We describe otinv, an offline tool that reads passive captures or
Zeek/Malcolm logs from a control network and writes a one-page,
plain-English "what to fix first" report, an asset inventory in the
vocabulary of CISA's Cybersecurity Performance Goals (CPG) 2.0, and an
appendix in which every finding cites the log lines it came from and,
when otinv ran Zeek on the capture itself, the packets behind its
connection-level lines. The analysis is deterministic and rule-based, so the same capture
always gives the same report and every rule can be read and edited. On a
scripted lab network otinv inventories every device and flags every scripted
problem. On 15 public ICS captures from CISA and the Zeek project it
recovers device identity for eight industrial protocols and ties every
connection-level evidence line in the findings to a packet. We propose a study measuring whether
operators with no security background can name the top actions after
reading the one-page report.

## 1. Introduction

Most community water systems in the US are small: 91% serve 10,000 people or
fewer (EPA Report to Congress, November 2024). They tend to lack staff and
security expertise more than tools. An EPA Office of Inspector General
passive scan of 1,062 larger systems found 97, serving about 26.6 million
people, with critical or high-risk issues (report 25-N-0004), and GAO found
that EPA had not assessed the sector's cyber risk (GAO-24-106744).

Monitoring is not the missing piece. CISA and INL publish Malcolm, a free
sensor platform built on Zeek and Suricata, and CISA's ICSNPP project adds
Zeek parsers for most industrial protocols. Volunteer programs such as DEF
CON Franklin put people on site. What a two-person utility still can't do is
read Zeek's logs and turn them into the inventory and documentation that
regulators and insurers ask for. CPG 2.0 asks for a regularly updated
inventory of all assets, with configurations, roles, drawings and tools for
OT, and suggests collecting network traffic between assets where OT logs
are not available.

otinv sits on top of those tools and does that last step. Its design
choices follow from who reads its output:

- the reader is an operator, not an analyst, so each finding is one plain
  sentence plus a concrete action, and the report is one page
- the person running it is a volunteer who has to defend each statement,
  so every finding cites its log lines, and its packets when otinv read the
  capture itself
- the data is critical infrastructure information, so nothing leaves the
  laptop, and a pseudonymized copy can be shared for review

## 2. Background and related work

Zeek turns packets into per-protocol logs. ICSNPP extends it with parsers
for BACnet, S7comm, EtherNet/IP and CIP, OPC UA Binary, Omron FINS, HART-IP,
ROC Plus, C37.118 and others, plus richer Modbus and DNP3 logs. Grashöfer et
al. argue for exactly this kind of protocol diversity in network security
monitors and show dissectors for non-IP industrial protocols integrated into
Zeek ("Advancing Protocol Diversity in Network Security Monitoring", arXiv
2106.12454, 2021). Manzella and Hastings build on CISA's BACnet parser to
train anomaly detectors on BACnet/IP traffic ("Enhancing Attack Detection
Capabilities in BACnet/IP Networks Using Machine-Learning Models", arXiv
2607.20686, 2026).

That line of work improves detection. otinv takes detection as given and
asks a different question: how to explain the result to someone who will
never read a Zeek log. GRASSMARLIN once drew passive ICS network maps, but
it is archived. Commercial OT platforms (Dragos, among others) produce
inventories and findings, and Dragos offers its platform free to small
utilities; otinv is meant to complement such programs, and to work where a
utility only has a laptop and a mirror port.

## 3. Design

```text
capture --(zeek -r, ICSNPP)--> zeek logs --> reader --> inventory, roles, map
        --> rules --> findings --> one-page report, appendix, CSV, diff
```

Input. otinv accepts a capture (it runs Zeek itself, natively, inside WSL
on Windows, or in a Docker container with no network), a folder of Zeek
logs, or an export of Zeek documents from Malcolm's API. The reader keeps
an allow-list of logs and fields and drops credentials as it parses, so
passwords never reach memory beyond the line being read.

Inventory. A host becomes a device only if it sent something, so scans of
empty addresses don't create phantom devices. MAC addresses seen with
several IPs are treated as a router's. Roles come from behaviour: a host
that answers Modbus, DNP3 or another industrial protocol is a controller; a
host that polls one regularly is an operator screen (HMI/SCADA); a host that
sends programming functions or opens configuration sessions to a controller
is an engineering workstation. Each role records the log line behind it.
Device identity (vendor, model, firmware, serial) is read where the traffic
carries it: EtherNet/IP List Identity, Modbus Read Device Identification,
BACnet I-Am and device properties, S7comm component identification, OPC UA
server descriptions, Omron FINS controller data, ROC Plus system
configuration and C37.118 configuration frames.

Findings. Six rule types cover the problems the plan lists: industrial
protocols to or from the internet, remote-access services on control-system
computers, logins sent in clear text, Modbus writes or DNP3 control from a
computer that doesn't normally send them, devices new since the last run,
and control-system devices using ordinary internet services. Every rule's
text, severity and thresholds live in an editable file. "Expected" writers
come from a site file, or, without one, from regular polling.

Evidence. Zeek logs say when and between which endpoints something
happened, not which packet it was. When otinv runs Zeek itself, it reads the
capture once more and matches each evidence line that names a TCP or UDP
connection to the first packet with the same time stamp and endpoints,
giving the frame number Wireshark shows. For a conn.log line that is the
connection's first packet; for a protocol log line it is the packet that
carried the message. Lines without ports (DHCP, identity replies attributed
from a payload address) keep only their log line, and so does everything
from a log folder or a Malcolm export, where otinv never sees the packets.
A CSV lists the evidence lines (up to 10,000 per finding) with a Wireshark
filter for each.

Reports. The one-page summary ranks actions by severity and by how many
devices they touch, and caps the list at five. Sentences are generated from
structured fields, never stored as text, so pseudonymizing a report is a
field-by-field swap; a final scan of the shared files for IP and MAC
addresses deletes the share if anything slipped through.

## 4. Evaluation

Lab captures. A synthetic lab network (three PLCs, an RTU, an HMI, an
engineering workstation, an office PC, DHCP/DNS) is generated as Zeek logs
and, separately, as raw packets. The scripted bad hour adds a Modbus write
from the office PC, VNC reachable from the internet on the HMI, telnet and
FTP logins on a PLC, a TeamViewer session dialing out from the engineering
workstation, an HMI browsing the web, Modbus answered from the internet, and
a new gateway. From the logs otinv finds all nine scripted problems and
nothing else, and inventories every device with the right role. From the
packets, through real Zeek 9.0.1 with ICSNPP, it finds the same eight (the
new-device finding needs a previous run), reads the EtherNet/IP and Modbus
identity, and ties every connection-level evidence line to its packet; the
test decodes the cited packet independently and checks it is the Modbus
write.

Public captures. To check protocols and capture formats the lab doesn't
cover, otinv runs on 15 public captures: CISA's ICSNPP test captures
(BSD-3-Clause) for BACnet, S7comm, OPC UA, Omron FINS, ROC Plus, C37.118,
HART-IP, C12.22, EtherNet/IP, Modbus and DNP3, and Zeek's own Modbus and
DNP3 test captures, including one derived from the 4SICS ICS lab. They
include pcapng, raw-IP and loopback link types. The tests check the
controller's role in 11 of them (one only once its public addresses are
declared as the plant's), read identity for eight protocols, and check the
findings against what is actually in them: a Modbus session with an internet address in one, a register write
from a host that never polls in the 4SICS capture, and DNP3 select/operate
from a non-polling host in another. Every connection-level evidence line
gets a packet number.

Determinism. Given the same input and the same report time stamp, two runs
produce byte-for-byte identical report files; the test suite checks this
on the lab's bad hour, and checks that a Malcolm export of the lab gives
the same findings and inventory as the logs.

What this does not show. All of these captures are synthetic or from test
suites. None comes from a working utility, and none was taken off a mirror
port on real PLCs (an OpenPLC and AutomationDirect CLICK lab is planned).
The evaluation shows the tool does what it is designed to do; it does not
yet show that operators understand the report.

## 5. Planned user study

Question: after reading the one-page report, can an operator with no
security background name the top three actions, in order?

Design: participants (small-utility operators and Franklin-style
volunteers, recruited through a partner program) read the report for a lab
capture with known problems, then answer, without the report, what they
would do first and why. A comparison group reads the same findings as a
conventional alert list. Measures: correct top-three actions, ranking,
time, and confidence. A short interview asks which inventory columns an
inspector or insurer has asked them for, which feeds back into the CSV.

This needs Cal Poly IRB approval before any participant is contacted, and
any capture from a real utility needs that utility's written authorization
and stays on encrypted storage.

## 6. Limitations

- Passive capture only sees what crosses the mirror port during the capture.
  Silent devices and traffic elsewhere are missed.
- Role inference is heuristic. A host that both polls and programs
  controllers is reported under its strongest role, with every reason
  listed.
- Identity depends on the traffic: a controller that is never asked for its
  identity during the capture has none in the report. HART-IP instruments
  behind a gateway have no address of their own to attach identity to.
- Rule severities are the author's judgement, informed by CPG 2.0, and have
  not been reviewed by utility staff or inspectors.

## 7. Conclusion

otinv shows that the gap between free ICS monitoring and what a small
utility can act on can be closed with deterministic, explainable rules and
plain language, without new sensors. What's left is evidence that the
report works for its readers: the lab capture on real PLCs, the user study,
and a pilot through a partner program with written authorization.

## Sources

- CISA, Cross-Sector Cybersecurity Performance Goals 2.0, December 2025.
- EPA, Report to Congress on drinking water system size, November 2024.
- EPA Office of Inspector General, report 25-N-0004.
- U.S. GAO, GAO-24-106744, August 2024.
- J. Grashöfer, P. Oettig, R. Sommer, T. Wojtulewicz, H. Hartenstein,
  "Advancing Protocol Diversity in Network Security Monitoring", arXiv
  2106.12454, 2021.
- D. Manzella, J. D. Hastings, "Enhancing Attack Detection Capabilities in
  BACnet/IP Networks Using Machine-Learning Models", arXiv 2607.20686, 2026.
- CISA ICSNPP, https://github.com/cisagov/ICSNPP
- CISA and INL, Malcolm, https://github.com/cisagov/Malcolm

Before submission: check the exact titles and URLs of the CISA, EPA and GAO
documents, and add a review of related explainability work.
