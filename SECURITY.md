# Security policy

otinv handles critical infrastructure data, so security reports get priority.

## Reporting a vulnerability

**Do not open a public issue.** Report it through GitHub's private
vulnerability reporting on this repository (Security > Report a
vulnerability). If that isn't possible, email **Londopy@protonmail.com**.

Never include real utility captures, logs or reports in a report. Reproduce
it with the lab fixtures or a capture you made yourself.

You'll get an acknowledgement within 72 hours, and an assessment within 7 days.

## Supported versions

| Version | Supported |
|---|---|
| Unreleased (main) | ✅ |

## Threat model

**In scope** (please report):

- Credentials (user names, passwords, cookies, URLs) reaching any output, the run file, or memory past the log reader.
- Real addresses, MACs, names or serials surviving `--pseudonymize`.
- otinv sending any network traffic other than `otinv update`'s requests to GitHub when you run it, or the Docker runner starting a container with network access.
- `otinv update` installing a file that doesn't match the release's `SHA256SUMS.txt`, or installing without asking.
- Crafted logs, captures or `.londopy` files that crash otinv, exhaust memory, or write outside the output folder.
- A finding that cites evidence that doesn't support it.

**Out of scope:**

- Network devices the tool can't see because they were silent during the capture. That is a documented limit.
- Vulnerabilities in Zeek, ICSNPP or Docker themselves. Report those upstream.
- Zeek packages you installed with zkg that send data when Zeek loads them. otinv loads zkg packages (that's where ICSNPP lives), but not `site/local.zeek`.
- Someone with access to an unencrypted report folder reading it. Protecting that folder is the operator's job, as `README-SENSITIVE.txt` says.

## Binaries

Release binaries are not code-signed. Every release ships
`SHA256SUMS.txt`. Check a download against it before running it.
