# Zeek with CISA's ICSNPP parsers, for `otinv analyze capture.pcap --runner docker`.
#
#   docker build -t otinv-zeek:local docker/zeek-icsnpp
#
# Building needs the internet once (base image and packages). Running it
# doesn't: otinv starts it with --network none and the capture mounted
# read-only.
#
# Status: a starting point, not yet tested. Check that the ZEEK_VERSION tag
# exists on Docker Hub, and that each package builds against it, before
# relying on it in the field.

ARG ZEEK_VERSION=9.0.1
FROM zeek/zeek:${ZEEK_VERSION}

# the ICSNPP parsers are compiled plugins
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential cmake git \
 && rm -rf /var/lib/apt/lists/*

RUN zkg autoconfig --force \
 && zkg install --force \
      icsnpp-bacnet icsnpp-bsap icsnpp-dnp3 icsnpp-enip icsnpp-ethercat \
      icsnpp-genisys icsnpp-hart-ip icsnpp-modbus icsnpp-omron-fins \
      icsnpp-opcua-binary icsnpp-profinet-io-cm icsnpp-roc-plus \
      icsnpp-s7comm icsnpp-synchrophasor icsnpp-ge-srtp icsnpp-c1222

# a separate step, so a failed install above can't be masked by the || here
RUN grep -q '^@load packages' "$(zeek-config --site_dir)/local.zeek" \
 || echo '@load packages' >> "$(zeek-config --site_dir)/local.zeek"

WORKDIR /out
