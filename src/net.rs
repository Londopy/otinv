// address classification: which addresses are this site's own devices, which
// are the public internet, and which are neither (multicast, broadcast).

use std::cmp::Ordering;
use std::net::IpAddr;

/// An address range like `10.20.0.0/16` or `fd00::/8`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    net: IpAddr,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Option<Self> {
        let (addr, prefix) = match s.trim().split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok()?),
            None => (s.trim(), 255),
        };
        let net: IpAddr = addr.parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        let prefix = if prefix == 255 { max } else { prefix };
        (prefix <= max).then_some(Self { net, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(n) & mask == u32::from(*a) & mask
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(n) & mask == u128::from(*a) & mask
            }
            _ => false,
        }
    }
}

/// Parses an address. IPv4-mapped IPv6 (`::ffff:10.0.0.5`) becomes plain
/// IPv4, so it is classified (and matched) like the device it is.
pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse::<IpAddr>().ok().map(|ip| ip.to_canonical())
}

/// Multicast, broadcast and unspecified addresses aren't devices.
pub fn is_device_address(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => !(v.is_multicast() || v.is_broadcast() || v.is_unspecified()),
        IpAddr::V6(v) => !(v.is_multicast() || v.is_unspecified()),
    }
}

/// Private, link-local, loopback or shared (CGNAT) space, or a range the site
/// file says is theirs.
pub fn is_local(ip: &IpAddr, extra: &[Cidr]) -> bool {
    if extra.iter().any(|c| c.contains(ip)) {
        return true;
    }
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v) => {
            let s = v.segments()[0];
            v.is_loopback() || (s & 0xfe00) == 0xfc00 || (s & 0xffc0) == 0xfe80
        }
    }
}

/// Somewhere on the public internet: not local and a real device address.
pub fn is_public(ip: &IpAddr, extra: &[Cidr]) -> bool {
    is_device_address(ip) && !is_local(ip, extra)
}

/// Sorts address strings numerically (10.0.0.9 before 10.0.0.10); anything
/// that doesn't parse sorts after, by text.
pub fn cmp_addr(a: &str, b: &str) -> Ordering {
    match (parse_ip(a), parse_ip(b)) {
        (Some(x), Some(y)) => x.cmp(&y),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => a.cmp(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn classifies_addresses() {
        for l in [
            "10.1.2.3",
            "192.168.0.10",
            "172.16.5.5",
            "169.254.1.1",
            "100.64.0.1",
            "fd00::1",
        ] {
            assert!(is_local(&ip(l), &[]), "{l}");
        }
        // documentation ranges count as public: the test fixtures use them
        for p in ["203.0.113.50", "198.51.100.7", "8.8.8.8", "2001:db8::1"] {
            assert!(is_public(&ip(p), &[]), "{p}");
        }
        for n in ["224.0.0.1", "255.255.255.255", "0.0.0.0", "ff02::1"] {
            assert!(!is_device_address(&ip(n)), "{n}");
        }
    }

    #[test]
    fn mapped_ipv6_is_ipv4() {
        let ip = parse_ip("::ffff:10.10.2.20").unwrap();
        assert_eq!(ip.to_string(), "10.10.2.20");
        assert!(is_local(&ip, &[]));
    }

    #[test]
    fn site_ranges_make_public_space_local() {
        let extra = vec![Cidr::parse("203.0.113.0/24").unwrap()];
        assert!(is_local(&ip("203.0.113.9"), &extra));
        assert!(is_public(&ip("198.51.100.9"), &extra));
    }

    #[test]
    fn cidr_parsing() {
        assert!(Cidr::parse("10.0.0.0/8")
            .unwrap()
            .contains(&ip("10.200.1.1")));
        assert!(!Cidr::parse("10.0.0.0/8").unwrap().contains(&ip("11.0.0.1")));
        assert!(Cidr::parse("10.0.0.5").unwrap().contains(&ip("10.0.0.5")));
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(&ip("1.2.3.4")));
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("fd00::/8").unwrap().contains(&ip("fd12::1")));
    }

    #[test]
    fn numeric_sort() {
        let mut v = vec!["10.0.0.10", "10.0.0.9", "zzz", "10.0.0.100"];
        v.sort_by(|a, b| cmp_addr(a, b));
        assert_eq!(v, vec!["10.0.0.9", "10.0.0.10", "10.0.0.100", "zzz"]);
    }
}
