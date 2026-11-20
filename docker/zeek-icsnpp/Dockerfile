# Zeek with CISA's ICSNPP parsers, for `otinv analyze capture.pcap --runner docker`.
#
#   docker build -t otinv-zeek:local docker/zeek-icsnpp
#
# Building needs the internet once (base image and packages). Running it
# doesn't: otinv starts it with --network none and the capture mounted
# read-only.

ARG ZEEK_VERSION=9.0.1
FROM zeek/zeek:${ZEEK_VERSION}

# the ICSNPP parsers are compiled plugins
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git \
 && rm -rf /var/lib/apt/lists/*

# the parsers whose logs otinv reads: their own test suites must pass
RUN zkg autoconfig --force \
 && zkg install --force icsnpp-modbus icsnpp-dnp3 icsnpp-enip

# the rest add protocol coverage (conn.log service names), and otinv reads
# device identity from some of their logs (BACnet, S7comm, OPC UA, FINS, ROC
# Plus, C37.118; tests/public_traces.rs checks each against real captures).
# their own test suites are skipped: some fail against zeek 9 (icsnpp-hart-ip did, 2026-11) without affecting the parsing otinv
# relies on, and one failing self-test shouldn't block the whole image.
RUN zkg install --force --skiptests \
      icsnpp-bacnet icsnpp-bsap icsnpp-ethercat icsnpp-genisys icsnpp-hart-ip \
      icsnpp-omron-fins icsnpp-opcua-binary icsnpp-profinet-io-cm \
      icsnpp-roc-plus icsnpp-s7comm icsnpp-synchrophasor icsnpp-ge-srtp \
      icsnpp-c1222

# a separate step, so a failed install above can't be masked by the || here
RUN grep -q '^@load packages' "$(zeek-config --site_dir)/local.zeek" \
 || echo '@load packages' >> "$(zeek-config --site_dir)/local.zeek"

WORKDIR /out
