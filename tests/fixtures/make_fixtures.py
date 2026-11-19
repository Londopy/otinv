"""Writes the zeek-log fixtures for the scenario tests.

Two captures of the same small lab network, described as zeek would log them:

  lab-baseline/  a normal hour: an HMI polling three PLCs over Modbus and
                 EtherNet/IP and an RTU over DNP3, an engineering laptop, a
                 router that also does DNS/NTP, an office PC.
  malcolm-bad/   lab-bad as a Malcolm export: the same records with Malcolm's
                 field names, as a /mapi/document page and an NDJSON page.
  lab-bad/       the same hour plus every scripted bad scenario from the spec:
                 a rogue Modbus write (after a little polling, plus a refused
                 write), VNC reachable from the internet, a new device, Modbus
                 from the internet, FTP, telnet and web logins, TeamViewer
                 dialing out from the laptop, an HMI browsing the internet,
                 and a PLC firmware change.

Formats follow current zeek: modbus.log has a REQ and a RESP line per
transaction (`pdu_type`, zeek 6+) and names refused functions
`<FUNC>_EXCEPTION` (zeek 7.2+); dnp3.log has one line per exchange, and
unsolicited responses have no request.

All addresses are private lab ranges or the documentation ranges
198.51.100.0/24 and 203.0.113.0/24 (which otinv treats as internet).
The password below is a made-up string the tests check never leaks.

Run from the repo root:  python tests/fixtures/make_fixtures.py
"""

import json
import os

BASE = 1793520000.0  # 2026-11-01 08:00:00 UTC
HERE = os.path.dirname(os.path.abspath(__file__))

ROUTER_MAC = "00:11:22:33:44:01"
HOSTS = {
    "router": ("10.10.0.1", ROUTER_MAC),
    "plc1": ("10.10.1.10", "b8:27:eb:00:00:10"),  # OpenPLC on a Raspberry Pi
    "plc2": ("10.10.1.11", "00:d0:7c:00:00:11"),  # AutomationDirect CLICK
    "plc3": ("10.10.1.12", "00:1d:9c:00:00:12"),  # Rockwell CompactLogix
    "rtu": ("10.10.1.20", "00:a0:45:00:00:20"),  # DNP3 outstation
    "hmi": ("10.10.2.20", "00:0c:29:00:00:20"),
    "ews": ("10.10.2.30", "00:50:56:00:00:30"),
    # routed from another subnet: on the wire it carries the router's MAC
    "office": ("10.10.3.5", ROUTER_MAC),
    "moxa": ("10.10.1.50", "00:90:e8:00:00:50"),
}
SECRET = "Sup3rSecretLabPw"

CONN_FIELDS = (
    "ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration "
    "orig_bytes resp_bytes conn_state local_orig local_resp missed_bytes history "
    "orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes tunnel_parents "
    "orig_l2_addr resp_l2_addr"
).split()
CONN_TYPES = (
    "time string addr port addr port enum string interval count count string bool bool "
    "count string count count count count set[string] string string"
).split()


def header(path, fields, types):
    return (
        "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n"
        f"#path\t{path}\n#open\t2026-11-01-08-00-00\n"
        "#fields\t" + "\t".join(fields) + "\n#types\t" + "\t".join(types) + "\n"
    )


def write_tsv(d, name, fields, types, rows):
    with open(os.path.join(d, f"{name}.log"), "w", newline="\n") as f:
        f.write(header(name, fields.split(), types.split()))
        for row in rows:
            f.write("\t".join(row) + "\n")
        f.write("#close\t2026-11-01-09-00-00\n")


class Lab:
    def __init__(self):
        self.conn = []
        self.modbus = []
        self.dnp3 = []
        self.ftp = []
        self.http = []
        self.dhcp = []
        self.identity = []
        self.modbus_ident = []
        self.n = 0

    def uid(self):
        self.n += 1
        return f"C{self.n:05d}lab"

    def addr(self, who):
        if who in HOSTS:
            return HOSTS[who]
        return (who, ROUTER_MAC)  # internet addresses arrive through the router

    def c(self, t, src, dst, port, proto="tcp", service="-", answered=True, dur=1.0):
        (sip, smac), (dip, dmac) = self.addr(src), self.addr(dst)
        uid = self.uid()
        if proto == "tcp":
            hist, state = ("ShADadFf", "SF") if answered else ("S", "S0")
        else:
            hist, state = ("Dd", "SF") if answered else ("D", "S0")
        rb = "300" if answered else "0"
        rp = "4" if answered else "0"
        self.conn.append(
            [
                f"{BASE + t:.6f}", uid, sip, "49152", dip, str(port), proto, service,
                f"{dur:.6f}", "120", rb, state, "T", "T", "0", hist, "4", "280", rp,
                "460", "-", smac, dmac if answered else "-",
            ]
        )
        return uid

    def mb(self, t, src, dst, func, uid, refused=False):
        """One Modbus transaction: a REQ line and a RESP line, like zeek 6+."""
        s, d = HOSTS[src][0], HOSTS[dst][0]
        self.modbus.append([f"{BASE + t:.6f}", uid, s, "49152", d, "502", func, "REQ", "-"])
        resp = f"{func}_EXCEPTION" if refused else func
        exc = "ILLEGAL_DATA_ADDRESS" if refused else "-"
        self.modbus.append(
            [f"{BASE + t + 0.01:.6f}", uid, s, "49152", d, "502", resp, "RESP", exc]
        )

    def dn(self, t, src, dst, request, reply, uid):
        self.dnp3.append(
            [f"{BASE + t:.6f}", uid, HOSTS[src][0], "49152", HOSTS[dst][0], "20000",
             request, reply, "0"]
        )

    def write(self, name):
        d = os.path.join(HERE, name)
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "conn.log"), "w", newline="\n") as f:
            f.write(header("conn", CONN_FIELDS, CONN_TYPES))
            for row in self.conn:
                f.write("\t".join(row) + "\n")
            f.write("#close\t2026-11-01-09-00-00\n")
        write_tsv(d, "modbus", "ts uid id.orig_h id.orig_p id.resp_h id.resp_p func pdu_type exception",
                  "time string addr port addr port string string string", self.modbus)
        write_tsv(d, "dnp3", "ts uid id.orig_h id.orig_p id.resp_h id.resp_p fc_request fc_reply iin",
                  "time string addr port addr port string string count", self.dnp3)
        write_tsv(d, "dhcp", "ts uids client_addr server_addr mac host_name assigned_addr lease_time msg_types",
                  "time set[string] addr addr string string addr interval vector[string]", self.dhcp)
        if self.ftp:
            write_tsv(d, "ftp", "ts uid id.orig_h id.orig_p id.resp_h id.resp_p user password command arg reply_code reply_msg",
                      "time string addr port addr port string string string string count string", self.ftp)
        if self.http:
            write_tsv(d, "http", "ts uid id.orig_h id.orig_p id.resp_h id.resp_p method host uri username password status_code",
                      "time string addr port addr port string string string string string count", self.http)
        if self.modbus_ident:
            write_tsv(d, "modbus_read_device_identification",
                      "ts uid id.orig_h id.orig_p id.resp_h id.resp_p is_orig source_h source_p "
                      "destination_h destination_p func object_id_code object_id object_value",
                      "time string addr port addr port bool addr port addr port string string string string",
                      self.modbus_ident)
        # ICSNPP-ENIP identity replies, in zeek's JSON format (tests the JSON reader)
        with open(os.path.join(d, "cip_identity.log"), "w", newline="\n") as f:
            for rec in self.identity:
                f.write(json.dumps(rec) + "\n")


def baseline(lab, firmware="30.11"):
    # the HMI polls every PLC and the RTU all hour
    for i in range(12):
        t = i * 300.0
        u1 = lab.c(t, "hmi", "plc1", 502, service="modbus", dur=290)
        lab.mb(t + 1, "hmi", "plc1", "READ_HOLDING_REGISTERS", u1)
        u2 = lab.c(t + 2, "hmi", "plc2", 502, service="modbus", dur=290)
        lab.mb(t + 3, "hmi", "plc2", "READ_COILS", u2)
        lab.c(t + 4, "hmi", "plc3", 44818, service="enip", dur=290)
        u3 = lab.c(t + 5, "hmi", "rtu", 20000, service="dnp3", dur=290)
        lab.dn(t + 6, "hmi", "rtu", "READ", "RESPONSE", u3)
    # the RTU reports an alarm on its own: no request, so not a poll by anyone
    lab.dn(1500.0, "hmi", "rtu", "-", "UNSOLICITED_RESPONSE", "C00000unsol")
    # the operator changes a setpoint and starts a pump: expected control
    u = lab.c(1800.0, "hmi", "plc1", 502, service="modbus")
    lab.mb(1800.5, "hmi", "plc1", "WRITE_SINGLE_REGISTER", u)
    u = lab.c(1810.0, "hmi", "rtu", 20000, service="dnp3")
    lab.dn(1810.5, "hmi", "rtu", "DIRECT_OPERATE", "RESPONSE", u)
    # engineering laptop: OpenPLC's web page and an EtherNet/IP identity query
    lab.c(600.0, "ews", "plc1", 8080, service="http", dur=40)
    u = lab.c(610.0, "ews", "plc3", 44818, proto="udp", service="enip")
    lab.identity.append(
        {
            "ts": BASE + 610.2, "uid": u, "id.orig_h": HOSTS["ews"][0], "id.orig_p": 49152,
            "id.resp_h": HOSTS["plc3"][0], "id.resp_p": 44818, "is_orig": False,
            "source_h": HOSTS["plc3"][0], "destination_h": HOSTS["ews"][0],
            "vendor_id": 1, "vendor_name": "Rockwell Automation/Allen-Bradley",
            "device_type_name": "Programmable Logic Controller",
            "product_name": "1769-L33ER/A LOGIX5333ER", "revision": firmware,
            "serial_number": "0x60a1b2c3", "socket_address": HOSTS["plc3"][0],
        }
    )
    # network services on the router
    lab.c(5.0, "hmi", "router", 53, proto="udp", service="dns")
    lab.c(6.0, "ews", "router", 123, proto="udp", service="ntp")
    lab.c(7.0, "office", "router", 53, proto="udp", service="dns")
    # the office PC browses the web: plain IT, not a finding
    lab.c(100.0, "office", "198.51.100.20", 443, service="ssl")
    # the HMI probes an empty address: must not become a device
    lab.c(900.0, "hmi", "10.10.1.99", 502, answered=False)
    lab.dhcp.append(
        [f"{BASE + 2.0:.6f}", "C00000dhcp", "0.0.0.0", "10.10.0.1", "3c:52:82:00:00:05",
         "OFFICE-PC1", "10.10.3.5", "86400.000000", "REQUEST,ACK"]
    )


def bad(lab):
    baseline(lab, firmware="33.11")
    # rogue writes from the office PC: a few reads to look around, one write
    # that works and one the PLC refuses. 3 polls is far below min_polls.
    u = lab.c(2000.0, "office", "plc1", 502, service="modbus", dur=30)
    for i in range(3):
        lab.mb(2000.1 + i, "office", "plc1", "READ_COILS", u)
    lab.mb(2004.0, "office", "plc1", "WRITE_SINGLE_COIL", u)
    lab.mb(2005.0, "office", "plc1", "WRITE_MULTIPLE_REGISTERS", u, refused=True)
    # VNC on the HMI, from the internet and from the laptop
    lab.c(2100.0, "203.0.113.50", "hmi", 5900, service="rfb", dur=600)
    lab.c(2200.0, "ews", "hmi", 5900, service="rfb", dur=60)
    # a new Moxa gateway, polled by the HMI
    for i in range(3):
        u = lab.c(2300.0 + i * 60, "hmi", "moxa", 502, service="modbus")
        lab.mb(2300.5 + i * 60, "hmi", "moxa", "READ_INPUT_REGISTERS", u)
    # Modbus from the internet, answered by PLC1
    lab.c(2400.0, "198.51.100.66", "plc1", 502, service="modbus")
    # FTP and telnet logins to PLC2, a basic-auth web login to PLC1
    u = lab.c(2500.0, "ews", "plc2", 21, service="ftp", dur=20)
    lab.ftp.append(
        [f"{BASE + 2500.5:.6f}", u, HOSTS["ews"][0], "49152", HOSTS["plc2"][0], "21",
         "admin", SECRET, "PASS", SECRET, "230", "Password required for admin"]
    )
    # the laptop asks PLC2 who it is; ICSNPP logs the request and each object
    u = lab.c(2550.0, "ews", "plc2", 502, service="modbus")
    ews, plc2 = HOSTS["ews"][0], HOSTS["plc2"][0]
    for orig, code, name, value in (("T", "0x00", "Basic Device Identification", "-"),
                                    ("F", "0x00", "VendorName", "AutomationDirect"),
                                    ("F", "0x01", "ProductCode", "C0-12DD1E-D"),
                                    ("F", "0x02", "MajorMinorVersion", "3.41")):
        src, sp, dst, dp = (ews, "49152", plc2, "502") if orig == "T" else (plc2, "502", ews, "49152")
        lab.modbus_ident.append([f"{BASE + 2550.5:.6f}", u, ews, "49152", plc2, "502", orig,
                                 src, sp, dst, dp, "ENCAP_INTERFACE_TRANSPORT", code, name, value])
    lab.c(2600.0, "ews", "plc2", 23, service="-", dur=30)
    u = lab.c(2650.0, "ews", "plc1", 8080, service="http", dur=5)
    lab.http.append(
        [f"{BASE + 2650.2:.6f}", u, HOSTS["ews"][0], "49152", HOSTS["plc1"][0], "8080",
         "GET", "10.10.1.10", f"/login?token={SECRET}", "admin", SECRET, "200"]
    )
    # the laptop restarts the RTU (an engineering function, not a write)
    u = lab.c(2680.0, "ews", "rtu", 20000, service="dnp3")
    lab.dn(2680.5, "ews", "rtu", "COLD_RESTART", "RESPONSE", u)
    # TeamViewer on the laptop dials out to its relay
    lab.c(2690.0, "ews", "198.51.100.30", 5938, dur=900)
    # the HMI browses the internet
    lab.c(2700.0, "hmi", "198.51.100.20", 443, service="ssl")


def malcolm_doc(dataset, ts, uid, orig, resp, extra):
    """One document the way Malcolm's Logstash pipeline stores a zeek record."""
    oh, op, om = orig
    rh, rp, rm = resp
    doc = {
        "timestamp": round(float(ts) * 1000),
        "event": {"provider": "zeek", "dataset": dataset},
        "zeek": {"uid": uid},
        "source": {"ip": oh},
        "destination": {"ip": rh},
    }
    for side, port, mac in (("source", op, om), ("destination", rp, rm)):
        if port not in (None, "-"):
            doc[side]["port"] = int(port)
        if mac not in (None, "-"):
            doc[side]["mac"] = mac
    for key, value in extra.items():
        target = doc
        *path, last = key.split(".")
        for p in path:
            target = target.setdefault(p, {})
        target[last] = value
    return doc


def write_malcolm(lab, name):
    """lab as a Malcolm export: page1.json is a /mapi/document response,
    page2.ndjson the rest of the documents one per line."""
    docs = []
    for r in lab.conn:
        (ts, uid, oh, op, rh, rp, proto, service, dur, ob, rb, state, _, _, _, hist,
         _, _, rpk, _, _, om, rm) = r
        extra = {"network.transport": proto, "zeek.conn.duration": float(dur),
                 "zeek.conn.orig_bytes": int(ob), "zeek.conn.resp_bytes": int(rb),
                 "zeek.conn.conn_state": state, "zeek.conn.history": hist,
                 "zeek.conn.resp_pkts": int(rpk)}
        if service != "-":
            extra["network.protocol"] = [service]
        docs.append(malcolm_doc("conn", ts, uid, (oh, op, om), (rh, rp, rm), extra))
    for ts, uid, oh, op, rh, rp, func, pdu, _ in lab.modbus:
        docs.append(malcolm_doc("modbus", ts, uid, (oh, op, None), (rh, rp, None), {
            "zeek.modbus.func": func,
            "zeek.modbus.network_direction": {"REQ": "request", "RESP": "response"}[pdu]}))
    for ts, uid, oh, op, rh, rp, req, rep, _ in lab.dnp3:
        extra = {"zeek.dnp3.fc_reply": rep}
        if req != "-":
            extra["zeek.dnp3.fc_request"] = req
        docs.append(malcolm_doc("dnp3", ts, uid, (oh, op, None), (rh, rp, None), extra))
    for ts, uid, oh, op, rh, rp, user, pw, *_ in lab.ftp:
        docs.append(malcolm_doc("ftp", ts, uid, (oh, op, None), (rh, rp, None),
                                {"related.user": [user], "related.password": [pw]}))
    for ts, uid, oh, op, rh, rp, _, _, _, user, pw, _ in lab.http:
        docs.append(malcolm_doc("http", ts, uid, (oh, op, None), (rh, rp, None),
                                {"related.user": [user], "related.password": [pw]}))
    for ts, uid, client, server, mac, host, assigned, *_ in lab.dhcp:
        docs.append(malcolm_doc("dhcp", ts, uid, (client, 68, mac), (server, 67, None), {
            "zeek.dhcp.host_name": host, "zeek.dhcp.assigned_ip": assigned, "zeek.dhcp.mac": mac}))
    # ICSNPP logs: Malcolm keeps each packet's own direction in source/destination
    for rec in lab.identity:
        keep = ["vendor_id", "vendor_name", "device_type_name", "product_name", "revision",
                "serial_number", "socket_address"]
        reply = not rec["is_orig"]
        sp, dp = (rec["id.resp_p"], rec["id.orig_p"]) if reply else (rec["id.orig_p"], rec["id.resp_p"])
        docs.append(malcolm_doc(
            "cip_identity", rec["ts"], rec["uid"],
            (rec["source_h"], sp, None), (rec["destination_h"], dp, None),
            {"network.is_orig": rec["is_orig"], **{f"zeek.cip_identity.{k}": rec[k] for k in keep}}))
    for ts, uid, _, _, _, _, orig, src, sp, dst, dp, _, code, obj, value in lab.modbus_ident:
        extra = {"network.is_orig": orig == "T",
                 "zeek.modbus_read_device_identification.object_id_code": code,
                 "zeek.modbus_read_device_identification.object_id": obj}
        if value != "-":
            extra["zeek.modbus_read_device_identification.object_value"] = value
        docs.append(malcolm_doc("modbus_read_device_identification", ts, uid,
                                (src, sp, None), (dst, dp, None), extra))
    # Malcolm folds zeek's conn_long records into conn, flagged zeek.conn.long;
    # one for the internet VNC session must not count as a second connection
    vnc = next(r for r in lab.conn if r[5] == "5900" and r[2] == "203.0.113.50")
    docs.append(malcolm_doc("conn", vnc[0], vnc[1], (vnc[2], vnc[3], vnc[21]), (vnc[4], vnc[5], vnc[22]), {
        "network.transport": "tcp", "network.protocol": ["rfb"], "zeek.conn.long": "true",
        "zeek.conn.duration": 300.0, "zeek.conn.orig_bytes": 50, "zeek.conn.resp_bytes": 900,
        "zeek.conn.history": "ShADad", "zeek.conn.conn_state": "S1", "zeek.conn.resp_pkts": 3}))
    d = os.path.join(HERE, name)
    os.makedirs(d, exist_ok=True)
    half = len(docs) // 2
    page1 = {"filter": {"event.provider": "zeek"}, "range": [0, 1793523600],
             "results": [{"_id": f"lab-{i}", "_index": "arkime_sessions3-261101", "_score": 0.0,
                          "_source": doc} for i, doc in enumerate(docs[:half])],
             "total": {"value": len(docs), "relation": "eq"},
             "shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}, "timed_out": False}
    with open(os.path.join(d, "page1.json"), "w", newline="\n") as f:
        json.dump(page1, f, indent=1)
        f.write("\n")
    with open(os.path.join(d, "page2.ndjson"), "w", newline="\n") as f:
        for doc in docs[half:]:
            f.write(json.dumps(doc) + "\n")


if __name__ == "__main__":
    b = Lab()
    baseline(b)
    b.write("lab-baseline")
    x = Lab()
    bad(x)
    x.write("lab-bad")
    write_malcolm(x, "malcolm-bad")
    print("wrote lab-baseline/, lab-bad/ and malcolm-bad/")
