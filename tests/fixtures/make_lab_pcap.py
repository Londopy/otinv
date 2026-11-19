"""Writes lab.pcap: the "bad hour" of the lab network as real packets.

This is the capture-path counterpart of make_fixtures.py. Instead of zeek
logs it writes Ethernet frames, so a real zeek (with CISA's ICSNPP parsers)
has to do the protocol work, and otinv's capture path can be tested end to
end:

    python tests/fixtures/make_lab_pcap.py target/lab.pcap
    otinv analyze target/lab.pcap -o target/lab-report --runner docker

Everything is synthetic: private lab addresses plus the documentation ranges
198.51.100.0/24 and 203.0.113.0/24. Standard library only. Checksums are
computed, though zeek runs with -C anyway.
"""

import socket
import struct
import sys

BASE = 1793520000  # 2026-11-01 08:00:00 UTC
SECRET = "Sup3rSecretLabPw"

ROUTER_MAC = "00:11:22:33:44:01"
HOSTS = {
    "router": ("10.10.0.1", ROUTER_MAC),
    "plc1": ("10.10.1.10", "b8:27:eb:00:00:10"),
    "plc2": ("10.10.1.11", "00:d0:7c:00:00:11"),
    "plc3": ("10.10.1.12", "00:1d:9c:00:00:12"),
    "rtu": ("10.10.1.20", "00:a0:45:00:00:20"),
    "hmi": ("10.10.2.20", "00:0c:29:00:00:20"),
    "ews": ("10.10.2.30", "00:50:56:00:00:30"),
    "office": ("10.10.3.5", "3c:52:82:00:00:05"),
}


def addr(who):
    if who in HOSTS:
        return HOSTS[who]
    return (who, ROUTER_MAC)  # internet addresses arrive through the router


def mac_bytes(m):
    return bytes(int(x, 16) for x in m.split(":"))


def csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class Pcap:
    def __init__(self):
        self.packets = []
        self.ip_id = 1

    def frame(self, t, src, dst, proto, l4, src_mac=None, dst_mac=None):
        (sip, smac), (dip, dmac) = addr(src), addr(dst)
        smac, dmac = src_mac or smac, dst_mac or dmac
        total = 20 + len(l4)
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, self.ip_id, 0x4000, 64, proto, 0,
                         socket.inet_aton(sip), socket.inet_aton(dip))
        ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
        self.ip_id += 1
        eth = mac_bytes(dmac) + mac_bytes(smac) + b"\x08\x00"
        self.packets.append((t, eth + ip + l4))

    def udp(self, t, src, dst, sport, dport, payload, **kw):
        sip, dip = addr(src)[0], addr(dst)[0]
        length = 8 + len(payload)
        hdr = struct.pack("!HHHH", sport, dport, length, 0)
        pseudo = socket.inet_aton(sip) + socket.inet_aton(dip) + struct.pack("!BBH", 0, 17, length)
        c = csum(pseudo + hdr + payload) or 0xFFFF
        self.frame(t, src, dst, 17, struct.pack("!HHHH", sport, dport, length, c) + payload, **kw)

    def tcp_seg(self, t, src, dst, sport, dport, seq, ack, flags, payload=b""):
        sip, dip = addr(src)[0], addr(dst)[0]
        hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
        pseudo = socket.inet_aton(sip) + socket.inet_aton(dip) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
        c = csum(pseudo + hdr + payload)
        hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
        self.frame(t, src, dst, 6, hdr + payload)

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for t, data in sorted(self.packets, key=lambda p: p[0]):
                sec = int(t)
                usec = int(round((t - sec) * 1e6))
                f.write(struct.pack("<IIII", sec, usec, len(data), len(data)))
                f.write(data)


SYN, ACK, PSH, FIN, RST = 0x02, 0x10, 0x08, 0x01, 0x04


class Tcp:
    """One TCP connection: handshake, data both ways, clean close."""

    def __init__(self, pcap, t, cli, srv, dport, sport=None):
        self.p, self.cli, self.srv, self.dport = pcap, cli, srv, dport
        self.sport = sport or 40000 + (pcap.ip_id % 20000)
        self.cseq, self.sseq = 1000, 5000
        self.t = BASE + t
        p = self.p
        p.tcp_seg(self.tick(), cli, srv, self.sport, dport, self.cseq, 0, SYN)
        p.tcp_seg(self.tick(), srv, cli, dport, self.sport, self.sseq, self.cseq + 1, SYN | ACK)
        self.cseq += 1
        self.sseq += 1
        p.tcp_seg(self.tick(), cli, srv, self.sport, dport, self.cseq, self.sseq, ACK)

    def tick(self, dt=0.001):
        self.t += dt
        return self.t

    def c2s(self, data, dt=0.01):
        self.t += dt
        self.p.tcp_seg(self.tick(), self.cli, self.srv, self.sport, self.dport, self.cseq, self.sseq, PSH | ACK, data)
        self.cseq += len(data)
        self.p.tcp_seg(self.tick(), self.srv, self.cli, self.dport, self.sport, self.sseq, self.cseq, ACK)

    def s2c(self, data, dt=0.005):
        self.t += dt
        self.p.tcp_seg(self.tick(), self.srv, self.cli, self.dport, self.sport, self.sseq, self.cseq, PSH | ACK, data)
        self.sseq += len(data)
        self.p.tcp_seg(self.tick(), self.cli, self.srv, self.sport, self.dport, self.cseq, self.sseq, ACK)

    def close(self):
        p = self.p
        p.tcp_seg(self.tick(), self.cli, self.srv, self.sport, self.dport, self.cseq, self.sseq, FIN | ACK)
        p.tcp_seg(self.tick(), self.srv, self.cli, self.dport, self.sport, self.sseq, self.cseq + 1, FIN | ACK)
        p.tcp_seg(self.tick(), self.cli, self.srv, self.sport, self.dport, self.cseq + 1, self.sseq + 1, ACK)


# ---- Modbus/TCP --------------------------------------------------------------

class Modbus:
    def __init__(self, conn):
        self.c, self.tid = conn, 1

    def tx(self, req_pdu, resp_pdu, unit=1):
        def mbap(pdu):
            return struct.pack("!HHHB", self.tid, 0, len(pdu) + 1, unit) + pdu
        self.c.c2s(mbap(req_pdu))
        self.c.s2c(mbap(resp_pdu))
        self.tid += 1

    def read_holding(self):
        self.tx(bytes([3]) + struct.pack("!HH", 0, 10), bytes([3, 20]) + bytes(20))

    def read_coils(self):
        self.tx(bytes([1]) + struct.pack("!HH", 0, 8), bytes([1, 1, 0x55]))

    def write_register(self):
        pdu = bytes([6]) + struct.pack("!HH", 4, 1234)
        self.tx(pdu, pdu)

    def write_coil(self):
        pdu = bytes([5]) + struct.pack("!HH", 2, 0xFF00)
        self.tx(pdu, pdu)

    def write_registers_refused(self):
        req = bytes([16]) + struct.pack("!HHB", 900, 2, 4) + struct.pack("!HH", 1, 2)
        self.tx(req, bytes([0x90, 0x02]))  # exception: illegal data address

    def read_device_identification(self, objects):
        """Function 43, MEI type 14, basic objects: what ICSNPP logs as identity."""
        body = b"".join(bytes([oid, len(v)]) + v.encode() for oid, v in objects)
        resp = bytes([0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, len(objects)]) + body
        self.tx(bytes([0x2B, 0x0E, 0x01, 0x00]), resp)


# ---- DNP3 --------------------------------------------------------------------

def crc_dnp(data):
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return struct.pack("<H", (~crc) & 0xFFFF)


def dnp3_frame(app, master_to_outstation, seq):
    """One link-layer frame carrying a single-fragment application message."""
    user = bytes([0xC0 | (seq & 0x3F)]) + app  # transport: FIR|FIN
    ctrl = 0xC4 if master_to_outstation else 0x44
    dest, src = (10, 1) if master_to_outstation else (1, 10)
    head = bytes([0x05, 0x64, 5 + len(user), ctrl]) + struct.pack("<HH", dest, src)
    out = head + crc_dnp(head)
    for i in range(0, len(user), 16):
        block = user[i:i + 16]
        out += block + crc_dnp(block)
    return out


def dnp3_tx(conn, func, objects=b"", seq=0):
    req = bytes([0xC0 | seq, func]) + objects
    resp = bytes([0xC0 | seq, 0x81, 0x00, 0x00])
    conn.c2s(dnp3_frame(req, True, seq))
    conn.s2c(dnp3_frame(resp, False, seq))


# ---- EtherNet/IP List Identity ----------------------------------------------

def enip_list_identity_reply(ip):
    name = b"1769-L33ER/A LOGIX5333ER"
    item = struct.pack("<H", 1)  # encapsulation protocol version
    item += struct.pack("!HH4s8s", 2, 44818, socket.inet_aton(ip), bytes(8))
    item += struct.pack("<HHHBBHI", 1, 0x0E, 0x59, 33, 11, 0x0030, 0x60A1B2C3)
    item += bytes([len(name)]) + name + bytes([3])
    data = struct.pack("<HHH", 1, 0x000C, len(item)) + item
    return struct.pack("<HHII8sI", 0x0063, len(data), 0, 0, b"otinvlab", 0) + data


def enip_list_identity_request():
    return struct.pack("<HHII8sI", 0x0063, 0, 0, 0, b"otinvlab", 0)


# ---- DHCP, DNS, NTP ---------------------------------------------------------

def dhcp(op, xid, mac, yiaddr, msg_type, hostname=None, server=None):
    pkt = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", op, 1, 6, 0, xid, 0, 0x8000,
                      bytes(4), socket.inet_aton(yiaddr), bytes(4), bytes(4),
                      mac_bytes(mac) + bytes(10), bytes(64), bytes(128))
    opts = b"\x63\x82\x53\x63" + bytes([53, 1, msg_type])
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname.encode()
    if server:
        opts += bytes([54, 4]) + socket.inet_aton(server)
    opts += bytes([50, 4]) + socket.inet_aton(yiaddr) + bytes([255])
    return pkt + opts


def dns_query(qid, name, response=False):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    flags = 0x8183 if response else 0x0100  # response: NXDOMAIN
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + q + struct.pack("!HH", 1, 1)


def ntp(mode):
    return bytes([(4 << 3) | mode]) + bytes(47)


def build():
    p = Pcap()
    # DHCP for the office PC (its real MAC, before it is routed)
    p.udp(BASE + 2.0, "0.0.0.0", "255.255.255.255", 68, 67,
          dhcp(1, 0x1234, HOSTS["office"][1], "10.10.3.5", 3, hostname="OFFICE-PC1"),
          src_mac=HOSTS["office"][1], dst_mac="ff:ff:ff:ff:ff:ff")
    p.udp(BASE + 2.1, "router", "10.10.3.5", 67, 68,
          dhcp(2, 0x1234, HOSTS["office"][1], "10.10.3.5", 5, server="10.10.0.1"),
          dst_mac=HOSTS["office"][1])
    # infrastructure
    p.udp(BASE + 5.0, "hmi", "router", 53001, 53, dns_query(7, "historian.lab"))
    p.udp(BASE + 5.01, "router", "hmi", 53, 53001, dns_query(7, "historian.lab", True))
    p.udp(BASE + 6.0, "ews", "router", 123, 123, ntp(3))
    p.udp(BASE + 6.01, "router", "ews", 123, 123, ntp(4))

    # the HMI polls PLC1, PLC2 and the RTU, one long connection each
    plc1 = Modbus(Tcp(p, 0.0, "hmi", "plc1", 502))
    plc2 = Modbus(Tcp(p, 0.5, "hmi", "plc2", 502))
    rtu = Tcp(p, 1.0, "hmi", "rtu", 20000)
    # packets on one connection must be built in time order, or their sequence
    # numbers run backwards and zeek drops the later ones as retransmissions
    crob = bytes([0x0C, 0x01, 0x17, 0x01, 0x00, 0x03, 0x01]) + struct.pack("<II", 100, 100) + b"\0"
    seq = 0
    for i in range(12):
        if i == 6:
            plc1.c.t = BASE + 1800
            plc1.write_register()  # the operator's setpoint change: expected
        plc1.c.t = BASE + i * 300 + 1
        plc1.read_holding()
        plc2.c.t = BASE + i * 300 + 3
        plc2.read_coils()
        rtu.t = BASE + i * 300 + 6
        dnp3_tx(rtu, 0x01, bytes([0x3C, 0x01, 0x06]), seq=seq % 16)  # READ class 0
        seq += 1
        if i == 6:
            rtu.t = BASE + 1810
            dnp3_tx(rtu, 0x05, crob, seq=seq % 16)  # DIRECT_OPERATE a pump: expected
            seq += 1
    for c in (plc1.c, plc2.c, rtu):
        c.t = BASE + 3590
        c.close()

    # PLC3: EtherNet/IP identity query from the engineering laptop
    p.udp(BASE + 610.0, "ews", "plc3", 50000, 44818, enip_list_identity_request())
    p.udp(BASE + 610.2, "plc3", "ews", 44818, 50000, enip_list_identity_reply("10.10.1.12"))

    # rogue writes from the office PC (routed: router MAC on the wire)
    rogue = Modbus(Tcp(p, 2000.0, "office", "plc1", 502))
    for _ in range(3):
        rogue.read_coils()
    rogue.write_coil()
    rogue.write_registers_refused()
    rogue.c.close()

    # VNC on the HMI from the internet and from the laptop
    for t, src in ((2100.0, "203.0.113.50"), (2200.0, "ews")):
        v = Tcp(p, t, src, "hmi", 5900)
        v.s2c(b"RFB 003.008\n")
        v.c2s(b"RFB 003.008\n")
        v.s2c(bytes([1, 2]))
        v.close()

    # Modbus answered for someone on the internet
    m = Modbus(Tcp(p, 2400.0, "198.51.100.66", "plc1", 502))
    m.read_holding()
    m.c.close()

    # FTP, telnet and basic-auth web logins from the laptop
    f = Tcp(p, 2500.0, "ews", "plc2", 21)
    f.s2c(b"220 CLICK FTP ready\r\n")
    f.c2s(b"USER admin\r\n")
    f.s2c(b"331 Password required for admin\r\n")
    f.c2s(f"PASS {SECRET}\r\n".encode())
    f.s2c(b"230 Logged in\r\n")
    f.c2s(b"QUIT\r\n")
    f.s2c(b"221 Bye\r\n")
    f.close()
    # the laptop asks PLC2 who it is (Modbus Read Device Identification)
    ident = Modbus(Tcp(p, 2550.0, "ews", "plc2", 502))
    ident.read_device_identification([(0, "AutomationDirect"), (1, "C0-12DD1E-D"), (2, "3.41")])
    ident.c.close()
    tn = Tcp(p, 2600.0, "ews", "plc2", 23)
    tn.s2c(b"login: ")
    tn.c2s(b"admin\r\n")
    tn.s2c(b"Password: ")
    tn.c2s(SECRET.encode() + b"\r\n")
    tn.close()
    import base64
    cred = base64.b64encode(f"admin:{SECRET}".encode()).decode()
    h = Tcp(p, 2650.0, "ews", "plc1", 8080)
    h.c2s(f"GET /login?token={SECRET} HTTP/1.1\r\nHost: 10.10.1.10\r\nAuthorization: Basic {cred}\r\n\r\n".encode())
    h.s2c(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    h.close()

    # the laptop restarts the RTU (DNP3 COLD_RESTART)
    r = Tcp(p, 2680.0, "ews", "rtu", 20000)
    dnp3_tx(r, 0x0D)
    r.close()

    # TeamViewer on the laptop dials out to a relay
    tv = Tcp(p, 2690.0, "ews", "198.51.100.30", 5938)
    tv.c2s(bytes([0x17, 0x24, 0x0A, 0x20]) + bytes(60))
    tv.s2c(bytes([0x17, 0x24, 0x0B, 0x30]) + bytes(60))
    tv.close()

    # the HMI browses the internet
    w = Tcp(p, 2700.0, "hmi", "198.51.100.20", 443)
    w.c2s(bytes([0x16, 0x03, 0x01, 0x00, 0x05]) + bytes(5))
    w.s2c(bytes([0x16, 0x03, 0x03, 0x00, 0x05]) + bytes(5))
    w.close()

    # a handshake-only scan of PLC2 from the office PC: no role for the scanner
    s = Tcp(p, 2800.0, "office", "plc2", 102)
    p.tcp_seg(s.tick(), "office", "plc2", s.sport, 102, s.cseq, s.sseq, RST | ACK)
    return p


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "lab.pcap"
    build().write(out)
    print(f"wrote {out}")
