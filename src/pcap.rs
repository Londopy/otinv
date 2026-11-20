// frame numbers for evidence (NFR-3). zeek logs say when something happened
// and between which endpoints, not which packet it was. this reads the
// capture once and gives each evidence line the number Wireshark shows for
// its packet: the first one with the line's time stamp and endpoints.
//
// reads classic pcap (micro- and nanosecond) and pcapng. packets it can't
// decode are counted but never matched; their evidence keeps its log line.

use crate::model::Run;
use anyhow::{bail, Context, Result};
use std::collections::{HashMap, HashSet};
use std::io::{BufReader, ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

type End = (IpAddr, u16);
/// Time in microseconds, then both endpoints in a fixed order.
type Key = (i64, End, End);

/// Larger than any real packet or pcapng block; anything bigger is corruption.
const MAX_BLOCK: usize = 64 << 20;

fn key(usec: i64, a: End, b: End) -> Key {
    if a <= b {
        (usec, a, b)
    } else {
        (usec, b, a)
    }
}

/// Fills in `frame` on every evidence line that matches a packet in the
/// capture. Returns how many lines got one.
pub fn number_frames(path: &Path, run: &mut Run) -> Result<usize> {
    let want: HashSet<Key> = run
        .evidence_mut()
        .filter_map(|e| {
            let (sp, dp) = e.ports?;
            let src = e.src.as_deref()?.parse().ok()?;
            let dst = e.dst.as_deref()?.parse().ok()?;
            Some(key((e.ts? * 1e6).round() as i64, (src, sp), (dst, dp)))
        })
        .collect();
    if want.is_empty() {
        return Ok(0);
    }
    let found = scan(path, &want).with_context(|| format!("Reading {}", path.display()))?;
    let mut n = 0;
    for e in run.evidence_mut() {
        let (Some((sp, dp)), Some(ts)) = (e.ports, e.ts) else {
            continue;
        };
        let (Some(src), Some(dst)) = (
            e.src.as_deref().and_then(|s| s.parse().ok()),
            e.dst.as_deref().and_then(|s| s.parse().ok()),
        ) else {
            continue;
        };
        if let Some(f) = found.get(&key((ts * 1e6).round() as i64, (src, sp), (dst, dp))) {
            e.frame = Some(*f);
            n += 1;
        }
    }
    Ok(n)
}

fn scan(path: &Path, want: &HashSet<Key>) -> Result<HashMap<Key, u64>> {
    let file = std::fs::File::open(path)?;
    let mut r = Packets::new(BufReader::with_capacity(1 << 20, file))?;
    let mut found = HashMap::new();
    let mut frame = 0u64;
    while let Some(p) = r.next()? {
        frame += 1;
        let (Some(usec), Some((a, b))) = (p.usec, endpoints(p.linktype, &p.data)) else {
            continue;
        };
        let k = key(usec, a, b);
        if want.contains(&k) {
            found.entry(k).or_insert(frame);
        }
    }
    Ok(found)
}

struct Packet {
    linktype: u16,
    /// None for pcapng simple packet blocks, which carry no time.
    usec: Option<i64>,
    data: Vec<u8>,
}

enum Format {
    Pcap {
        nanos: bool,
        linktype: u16,
    },
    /// Link type and ticks per second for each interface of the section.
    Pcapng {
        interfaces: Vec<(u16, u64)>,
    },
}

struct Packets<R> {
    r: R,
    big: bool,
    format: Format,
}

fn u16_at(b: &[u8], i: usize, big: bool) -> u16 {
    let a = [b[i], b[i + 1]];
    if big {
        u16::from_be_bytes(a)
    } else {
        u16::from_le_bytes(a)
    }
}

fn u32_at(b: &[u8], i: usize, big: bool) -> u32 {
    let a = [b[i], b[i + 1], b[i + 2], b[i + 3]];
    if big {
        u32::from_be_bytes(a)
    } else {
        u32::from_le_bytes(a)
    }
}

/// Whole microseconds, cut off like libpcap does, which is what zeek logs.
fn usec(ticks: u64, per_sec: u64) -> i64 {
    (ticks as i128 * 1_000_000 / per_sec as i128) as i64
}

impl<R: Read> Packets<R> {
    fn new(mut r: R) -> Result<Self> {
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .context("not a capture: too short")?;
        let (big, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                let mut p = Self {
                    r,
                    big: false,
                    format: Format::Pcapng {
                        interfaces: Vec::new(),
                    },
                };
                p.section()?;
                return Ok(p);
            }
            _ => bail!("not a pcap or pcapng capture"),
        };
        let mut h = [0u8; 20];
        r.read_exact(&mut h).context("capture header cut off")?;
        let linktype = (u32_at(&h, 16, big) & 0xffff) as u16;
        Ok(Self {
            r,
            big,
            format: Format::Pcap { nanos, linktype },
        })
    }

    /// The rest of a pcapng section header block, after its type.
    fn section(&mut self) -> Result<()> {
        let mut h = [0u8; 8];
        self.r.read_exact(&mut h).context("pcapng header cut off")?;
        self.big = match h[4..8] {
            [0x1a, 0x2b, 0x3c, 0x4d] => true,
            [0x4d, 0x3c, 0x2b, 0x1a] => false,
            _ => bail!("pcapng section header has no byte-order magic"),
        };
        let len = u32_at(&h, 0, self.big) as usize;
        if !(28..=MAX_BLOCK).contains(&len) || !len.is_multiple_of(4) {
            bail!("pcapng section header has a bad length ({len})");
        }
        self.skip(len - 12)?;
        self.format = Format::Pcapng {
            interfaces: Vec::new(),
        };
        Ok(())
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        let got = std::io::copy(&mut (&mut self.r).take(n as u64), &mut std::io::sink())?;
        if got != n as u64 {
            bail!("capture cut off");
        }
        Ok(())
    }

    /// Reads exactly `buf.len()` bytes, or nothing at a clean end of file.
    fn read_or_end(&mut self, buf: &mut [u8]) -> Result<bool> {
        let mut got = 0;
        while got < buf.len() {
            match self.r.read(&mut buf[got..]) {
                Ok(0) if got == 0 => return Ok(false),
                Ok(0) => bail!("capture cut off"),
                Ok(n) => got += n,
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }

    fn next(&mut self) -> Result<Option<Packet>> {
        let (nanos, linktype) = match self.format {
            Format::Pcap { nanos, linktype } => (nanos, linktype),
            Format::Pcapng { .. } => return self.next_block(),
        };
        let mut h = [0u8; 16];
        if !self.read_or_end(&mut h)? {
            return Ok(None);
        }
        let (sec, frac) = (u32_at(&h, 0, self.big), u32_at(&h, 4, self.big));
        let len = u32_at(&h, 8, self.big) as usize;
        if len > MAX_BLOCK {
            bail!("packet record has a bad length ({len})");
        }
        let mut data = vec![0u8; len];
        self.r.read_exact(&mut data).context("capture cut off")?;
        let per_sec = if nanos { 1_000_000_000 } else { 1_000_000 };
        Ok(Some(Packet {
            linktype,
            usec: Some(usec(sec as u64 * per_sec + frac as u64, per_sec)),
            data,
        }))
    }

    /// The next packet block of a pcapng file, reading past the others.
    fn next_block(&mut self) -> Result<Option<Packet>> {
        loop {
            let mut t = [0u8; 4];
            if !self.read_or_end(&mut t)? {
                return Ok(None);
            }
            if t == [0x0a, 0x0d, 0x0d, 0x0a] {
                self.section()?;
                continue;
            }
            let kind = u32_at(&t, 0, self.big);
            let mut l = [0u8; 4];
            self.r.read_exact(&mut l).context("capture cut off")?;
            let len = u32_at(&l, 0, self.big) as usize;
            if !(12..=MAX_BLOCK).contains(&len) {
                bail!("pcapng block has a bad length ({len})");
            }
            let mut body = vec![0u8; len - 8];
            self.r.read_exact(&mut body).context("capture cut off")?;
            let body = &body[..len - 12];
            let big = self.big;
            let Format::Pcapng { interfaces } = &mut self.format else {
                unreachable!("pcapng blocks only come from a pcapng file")
            };
            let iface = |interfaces: &Vec<(u16, u64)>, id: usize| {
                interfaces
                    .get(id)
                    .copied()
                    .context("packet from an undeclared interface")
            };
            match kind {
                // interface description
                1 if body.len() >= 8 => {
                    let linktype = u16_at(body, 0, big);
                    interfaces.push((linktype, ts_resolution(&body[8..], big)));
                }
                // enhanced packet, and the obsolete packet block old tools
                // still write: the same layout after the interface id
                6 | 2 if body.len() >= 20 => {
                    let id = if kind == 6 {
                        u32_at(body, 0, big) as usize
                    } else {
                        u16_at(body, 0, big) as usize
                    };
                    let (linktype, per_sec) = iface(interfaces, id)?;
                    let ticks = (u32_at(body, 4, big) as u64) << 32 | u32_at(body, 8, big) as u64;
                    let cap = (u32_at(body, 12, big) as usize).min(body.len() - 20);
                    return Ok(Some(Packet {
                        linktype,
                        usec: Some(usec(ticks, per_sec)),
                        data: body[20..20 + cap].to_vec(),
                    }));
                }
                // simple packet: first interface, no time stamp
                3 if body.len() >= 4 => {
                    let (linktype, _) = iface(interfaces, 0)?;
                    return Ok(Some(Packet {
                        linktype,
                        usec: None,
                        data: body[4..].to_vec(),
                    }));
                }
                _ => {}
            }
        }
    }
}

/// Ticks per second from an interface's options (if_tsresol, code 9).
fn ts_resolution(mut opts: &[u8], big: bool) -> u64 {
    while opts.len() >= 4 {
        let (code, len) = (u16_at(opts, 0, big), u16_at(opts, 2, big) as usize);
        if code == 0 || opts.len() < 4 + len {
            break;
        }
        if code == 9 && len >= 1 {
            let v = opts[4];
            let exp = u32::from(v & 0x7f);
            let per_sec = if v & 0x80 == 0 {
                10u64.checked_pow(exp)
            } else {
                2u64.checked_pow(exp)
            };
            return per_sec.filter(|&n| n > 0).unwrap_or(1_000_000);
        }
        opts = opts.get(4 + len.div_ceil(4) * 4..).unwrap_or_default();
    }
    1_000_000
}

/// The TCP or UDP endpoints of a packet, or None for anything else.
fn endpoints(linktype: u16, d: &[u8]) -> Option<(End, End)> {
    let ip = match linktype {
        // ethernet, with any number of VLAN tags
        1 => {
            let mut i = 12;
            loop {
                let t = u16::from_be_bytes([*d.get(i)?, *d.get(i + 1)?]);
                match t {
                    0x8100 | 0x88a8 | 0x9100 => i += 4,
                    0x0800 | 0x86dd => break d.get(i + 2..)?,
                    _ => return None,
                }
            }
        }
        // BSD loopback
        0 | 108 => d.get(4..)?,
        // raw IP
        12 | 14 | 101 | 228 | 229 => d,
        // linux cooked capture v1 and v2
        113 => d.get(16..)?,
        276 => d.get(20..)?,
        _ => return None,
    };
    let (src, dst, proto, l4) = match ip.first()? >> 4 {
        4 => {
            let ihl = usize::from(ip[0] & 0x0f) * 4;
            let frag = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]) & 0x1fff;
            if ihl < 20 || frag != 0 {
                return None;
            }
            let a: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
            let b: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
            (
                IpAddr::V4(Ipv4Addr::from(a)),
                IpAddr::V4(Ipv4Addr::from(b)),
                ip[9],
                ip.get(ihl..)?,
            )
        }
        6 => {
            let a: [u8; 16] = ip.get(8..24)?.try_into().ok()?;
            let b: [u8; 16] = ip.get(24..40)?.try_into().ok()?;
            let (mut next, mut i) = (*ip.get(6)?, 40);
            // hop-by-hop, routing and destination options headers
            while matches!(next, 0 | 43 | 60) {
                next = *ip.get(i)?;
                i += (usize::from(*ip.get(i + 1)?) + 1) * 8;
            }
            (
                IpAddr::V6(Ipv6Addr::from(a)),
                IpAddr::V6(Ipv6Addr::from(b)),
                next,
                ip.get(i..)?,
            )
        }
        _ => return None,
    };
    if proto != 6 && proto != 17 {
        return None;
    }
    let sp = u16::from_be_bytes([*l4.first()?, *l4.get(1)?]);
    let dp = u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]);
    Some(((src, sp), (dst, dp)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp_frame(src: [u8; 4], sp: u16, dst: [u8; 4], dp: u16, vlan: bool) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        if vlan {
            f.extend([0x81, 0x00, 0x00, 0x0a]);
        }
        f.extend([0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0];
        ip.extend(src);
        ip.extend(dst);
        f.extend(ip);
        f.extend(sp.to_be_bytes());
        f.extend(dp.to_be_bytes());
        f.extend([0u8; 16]);
        f
    }

    fn pcap(packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        pcap_link(1, packets)
    }

    fn pcap_link(linktype: u32, packets: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
        let mut out = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
        out.extend([0u8; 8]);
        out.extend(65535u32.to_le_bytes());
        out.extend(linktype.to_le_bytes());
        for (sec, us, d) in packets {
            out.extend(sec.to_le_bytes());
            out.extend(us.to_le_bytes());
            out.extend((d.len() as u32).to_le_bytes());
            out.extend((d.len() as u32).to_le_bytes());
            out.extend(d);
        }
        out
    }

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let pad = body.len().div_ceil(4) * 4;
        let len = (12 + pad) as u32;
        let mut b = kind.to_le_bytes().to_vec();
        b.extend(len.to_le_bytes());
        b.extend(body);
        b.resize(8 + pad, 0);
        b.extend(len.to_le_bytes());
        b
    }

    fn write(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("otinv-pcap-{}-{name}", std::process::id()));
        std::fs::write(&p, bytes).unwrap();
        p
    }

    const A: [u8; 4] = [10, 0, 2, 20];
    const B: [u8; 4] = [10, 0, 1, 10];

    fn want(usec: i64, sp: u16, dp: u16) -> Key {
        key(usec, (IpAddr::from(A), sp), (IpAddr::from(B), dp))
    }

    #[test]
    fn classic_pcap_finds_the_packet() {
        let p = write(
            "a.pcap",
            &pcap(&[
                (100, 1, tcp_frame(A, 50000, B, 502, false)),
                (100, 500, tcp_frame(B, 502, A, 50000, true)),
                (100, 900, tcp_frame(A, 50001, B, 502, false)),
            ]),
        );
        let w: HashSet<Key> = [want(100_000_500, 50000, 502), want(100_000_900, 50001, 502)]
            .into_iter()
            .collect();
        let found = scan(&p, &w).unwrap();
        std::fs::remove_file(&p).unwrap();
        // the reply direction and a VLAN tag still match
        assert_eq!(found.get(&want(100_000_500, 50000, 502)), Some(&2));
        assert_eq!(found.get(&want(100_000_900, 50001, 502)), Some(&3));
    }

    #[test]
    fn pcapng_with_nanosecond_clock() {
        let mut f = block(
            0x0a0d0d0a,
            &[
                0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        );
        // ethernet, snaplen, if_tsresol = 9
        let mut idb = vec![1, 0, 0, 0, 0xff, 0xff, 0, 0];
        idb.extend([9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        f.extend(block(1, &idb));
        f.extend(block(5, &[0u8; 8]));
        // zeek cuts nanoseconds down to the microsecond, it doesn't round
        let ns: u64 = 100_000_000_700 * 1000 + 900;
        let d = tcp_frame(A, 40000, B, 20000, false);
        let mut epb = 0u32.to_le_bytes().to_vec();
        epb.extend(((ns >> 32) as u32).to_le_bytes());
        epb.extend((ns as u32).to_le_bytes());
        epb.extend((d.len() as u32).to_le_bytes());
        epb.extend((d.len() as u32).to_le_bytes());
        epb.extend(&d);
        f.extend(block(6, &epb));
        let p = write("b.pcapng", &f);
        let k = want(100_000_000_700, 40000, 20000);
        let found = scan(&p, &[k].into_iter().collect()).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert_eq!(found.get(&k), Some(&1));
    }

    #[test]
    fn packets_a_microsecond_apart_get_their_own_frames() {
        let d = || tcp_frame(A, 50000, B, 502, false);
        let p = write(
            "tight.pcap",
            &pcap(&[(100, 5, d()), (100, 6, d()), (100, 7, d())]),
        );
        let (k6, k7) = (want(100_000_006, 50000, 502), want(100_000_007, 50000, 502));
        let found = scan(&p, &[k6, k7].into_iter().collect()).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert_eq!((found.get(&k6), found.get(&k7)), (Some(&2), Some(&3)));
    }

    #[test]
    fn ipv6_udp_over_linux_cooked_v2() {
        let (a, b): (Ipv6Addr, Ipv6Addr) =
            ("fd00::20".parse().unwrap(), "fd00::10".parse().unwrap());
        let mut f = vec![0x86, 0xdd];
        f.resize(20, 0);
        let mut ip = vec![0x60, 0, 0, 0, 0, 8, 17, 64];
        ip.extend(a.octets());
        ip.extend(b.octets());
        f.extend(ip);
        f.extend(47808u16.to_be_bytes());
        f.extend(47808u16.to_be_bytes());
        f.extend([0, 8, 0, 0]);
        let p = write("sll2.pcap", &pcap_link(276, &[(100, 1, f)]));
        let k = key(100_000_001, (IpAddr::V6(a), 47808), (IpAddr::V6(b), 47808));
        let found = scan(&p, &[k].into_iter().collect()).unwrap();
        std::fs::remove_file(&p).unwrap();
        assert_eq!(found.get(&k), Some(&1));
    }

    #[test]
    fn unpadded_interface_option_is_not_a_crash() {
        let mut f = block(
            0x0a0d0d0a,
            &[
                0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ],
        );
        // an interface block whose if_name option (5 bytes) has no padding
        let mut idb = 1u32.to_le_bytes().to_vec();
        idb.extend(29u32.to_le_bytes());
        idb.extend([1, 0, 0, 0, 0xff, 0xff, 0, 0]);
        idb.extend([2, 0, 5, 0, b'e', b't', b'h', b'0', 0]);
        idb.extend(29u32.to_le_bytes());
        f.extend(idb);
        let p = write("unpadded.pcapng", &f);
        assert!(scan(&p, &HashSet::new()).unwrap().is_empty());
        std::fs::remove_file(&p).unwrap();
    }

    #[test]
    fn not_a_capture() {
        let p = write("c.pcap", b"conn.log, not a capture");
        assert!(scan(&p, &HashSet::new()).is_err());
        std::fs::remove_file(&p).unwrap();
    }
}
