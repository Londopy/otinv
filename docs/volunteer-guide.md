# Running otinv at a utility: a guide for volunteers

This is for someone helping a small utility, the way DEF CON Franklin and
Water Watch volunteers do. You take a capture of the control network, run
otinv on it, and walk the operator through what it found. Nothing here needs
a security background on the operator's side. It does need care on yours,
because what you carry home describes how to get into a water or power
system.

## Before you go

Get written permission. It should name the utility, the person who can
authorize it, the dates, the network segments, and that you will only listen
(a mirror port or a tap) and never scan or log in to anything. Keep a copy
with you. Without it, don't plug in.

Agree on where the data goes. The default that keeps everyone out of trouble:
the capture and the reports stay on your encrypted laptop (see
[Keeping the data safe](#keeping-the-data-safe)), the operator gets the report
folder on a USB stick they keep, and you delete the capture once the report
is done.

Bring:

- a laptop with otinv and Zeek (the Docker image, or Zeek in WSL; see the
  README's Install section), tested at home on the lab capture first
- a USB Ethernet adapter for the capture, so your normal network card stays
  off the plant network
- a passive tap if the switch can't mirror a port
- a USB stick for the operator's copy of the report

## Setting up the capture

The capture should see the traffic between the operator screens (HMI/SCADA)
and the controllers (PLCs, RTUs). On most small plants that's the switch the
SCADA server plugs into.

1. Ask whoever manages the switch to mirror the SCADA server's port, or the
   uplink between the control room and the field devices, to a free port. On
   unmanaged switches use a tap instead.
2. Plug your capture adapter into the mirror port.
3. Make sure your laptop can't talk on that port:
   - Windows: in the adapter's properties, untick Internet Protocol Version 4
     and Version 6. The adapter still captures, but sends nothing.
   - Linux: bring the interface up with no address and no DHCP client:
     `sudo ip link set eth1 up` and nothing else.

Capture for at least a full day, so the night shift, scheduled reports and
any vendor connections show up. A week is better if they'll let you leave a
box there. With Wireshark's `dumpcap` (it comes with Wireshark):

```sh
# list interfaces, then capture on yours into one-hour files
dumpcap -D
dumpcap -i 3 -b duration:3600 -w plant.pcapng

# afterwards, join them for otinv
mergecap -w plant-week.pcapng plant_*.pcapng
```

`tcpdump -i eth1 -s 0 -w plant.pcap` works too on Linux.

## Running otinv

```sh
otinv analyze plant-week.pcapng -o otinv-2026-11 --pseudonymize
```

Then open `otinv-2026-11/summary.txt`. That page is what the operator reads.
`appendix.html` has every finding, the log lines behind it (with packet
numbers for lines about a connection), and the network map.
`evidence.csv` lists the log lines behind every finding, with a Wireshark
filter for each line about a connection, if you want to check one in the
capture: paste the filter into Wireshark's display filter bar.

Expect the first run to flag things that are fine, like the SCADA server's
own vendor connection. That's what the site file is for.

## Filling in the site file

```sh
otinv site-template > site.toml
```

Sit down with the operator and fill it in:

- `name`: the utility's name, shown on every report
- `[names]`: what they call each device ("Well 2 PLC", "Control room HMI")
- `expected_writers`: the computers that are supposed to send control
  commands, usually just the SCADA server
- `local_networks`: any public addresses used inside the plant
- `[details."<address>"]`: where each device is, which drawings show it,
  where its program or configuration is backed up, and what software
  programs it. CISA's CPG 2.0 asks for these alongside the inventory, and no
  capture can see them. Write them once here and they appear in
  `inventory.csv` every month.

Run otinv again with `--site site.toml`. The site file names the devices, so
keep it with the reports.

## Going through it with the operator

Start from the "what to fix first" list in `summary.txt`. Each item says why
it matters and what to do, in plain words. For each one:

- show them the device it's about, by the name they use
- ask whether they knew about it. A remote-access tool the vendor installed
  years ago is a common answer
- agree who will do the fix and by when

Don't fix anything yourself, and don't touch the devices. otinv tells a
person what to do; the person who owns the system does it.

Leave them `inventory.csv`. It's the asset inventory an inspector or insurer
will ask for, with column names from CISA's guidance.

## Next month

Capture again the same way and pass last month's run:

```sh
otinv analyze plant-dec.pcapng -o otinv-2026-12 --site site.toml \
  --previous otinv-2026-11/run.londopy --pseudonymize
```

`diff.txt` says what changed: new devices, devices gone, firmware changes,
new and fixed problems. Pseudonymized aliases stay the same from month to
month, so a reviewer can follow the same device.

## Getting a second opinion

If you want another volunteer to look at a finding, send only the `share/`
folder. In it, every address, MAC address, device name, host name and serial
number is replaced with an alias, and what you wrote in `[details]`, plus
names and locations the devices announce about themselves, are withheld. otinv scans every shared file for addresses before it finishes and
deletes the folder if it finds one. It still describes a real utility's weak
spots, so send it encrypted and ask the reviewer to delete it afterwards.

Never send `run.londopy`, `pseudonym-map.csv`, the site file or the capture.
Those hold the real addresses.

## Keeping the data safe

A capture of a control network is critical infrastructure information. It
shows which devices accept commands from whom, and the reports list the weak
spots. otinv leaves encryption to you, because your disk encryption already
does it better than a tool could. Set it up before the first visit:

- Windows: turn on BitLocker for the whole disk (Settings, Privacy &
  security, Device encryption, or BitLocker on Pro editions). On Windows
  Home without device encryption, use a VeraCrypt container for the
  captures and reports.
- Linux: full-disk encryption (LUKS) from the installer, or a VeraCrypt or
  LUKS container for this work.
- USB sticks: an encrypted one (BitLocker To Go, or a VeraCrypt volume).
- Sending files: a 7-Zip archive with AES-256 and "Encrypt file names"
  ticked. Give the password over a different channel, like a phone call.

Keep as little as you can for as short as you can:

- Delete the capture once the report is done and the operator has their
  copy. Next month's diff only needs `run.londopy`, not the capture.
- otinv deletes Zeek's raw logs as soon as it has read them, because they
  can hold passwords and URLs. Don't use `--keep-logs` at a utility.
- Never put captures or reports in cloud storage, a ticket, a chat or an
  email without encryption, and never publish them.

## What otinv can't tell you

- Devices that stayed silent during the capture, or traffic that never
  crossed the mirror port, aren't in the report. A short capture misses
  things.
- It can't see drawings, backups or passwords on devices. Those come from
  the operator, through the site file.
- It reads traffic; it doesn't test anything. A clean report means nothing
  bad showed up in what was captured, not that the network is safe.
