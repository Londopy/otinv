//! otinv: a passive OT inventory reporter for small utilities.
//!
//! Zeek logs (or a capture zeek turns into logs) go in; an asset inventory,
//! a communication map and a plain-English "what to fix first" report come
//! out. Nothing is ever sent to the network being described.

pub mod analyze;
pub mod checks;
pub mod config;
pub mod diff;
pub mod londopy;
pub mod malcolm;
pub mod model;
pub mod net;
pub mod oui;
pub mod pcap;
pub mod pipeline;
pub mod pseudo;
pub mod report;
pub mod runner;
pub mod timefmt;
pub mod util;
pub mod zeek;
