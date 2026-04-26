# Security Policy

Mavi VPN is still early beta software. It has not had an independent security audit yet.

Please do not treat it like a production VPN for high-risk situations. It is useful for testing, learning, and feedback, but it still needs more review before I would recommend trusting it with sensitive traffic.

## Supported versions

Security fixes go into the `main` branch first.

I try to keep the latest tagged release usable, but for now this project moves fast and old releases are not guaranteed to receive patches.

## Reporting a security issue

Please do not open a public issue with exploit details.

If GitHub private vulnerability reporting is available on this repo, use that. If not, open a small public issue saying that you found a possible security problem and need a private contact. Do not include the actual details in that public issue.

Useful details to include in a private report:

* what component is affected, for example server, Linux client, Windows client, Android app, GUI, or Docker setup
* what version or commit you tested
* what you expected to happen
* what actually happened
* steps to reproduce, if you have them
* logs or packet captures, with secrets removed
* why you think this has security impact

I will try to respond as soon as I can. This is a small project, so I cannot promise enterprise-style response times, but I do take real reports seriously.

## Areas that need extra review

Reports around these areas are especially welcome:

* authentication and token handling
* certificate pinning
* tunnel routing and DNS behavior
* Docker and host networking setup
* client config storage
* Android VPN service behavior
* Windows routing and DNS rules
* Linux route cleanup
* QUIC transport edge cases
* anything that could leak traffic outside the tunnel

## Out of scope

Please do not run tests against systems you do not own.

For now, these are usually not treated as security bugs:

* missing features
* performance issues without a security impact
* issues that require full admin or root access on the user's own machine
* problems caused by intentionally unsafe local configuration

That said, if you are unsure, report it anyway.
