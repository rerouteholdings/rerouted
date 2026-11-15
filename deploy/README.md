# Deployment examples

These files are starting points for running rerouted on a Linux server. [Run a homeserver](../docs/run-a-homeserver.md) and [Run a call relay](../docs/run-a-call-relay.md) walk through using them.

| File | What it is | Install it as |
|---|---|---|
| `rerouted.service` | A systemd unit for one rerouted instance, locked down to its own data directory and the network | `/etc/systemd/system/rerouted.service` |
| `Caddyfile.example` | Caddy in front of rerouted, with certificates on demand for handle subdomains | `/etc/caddy/Caddyfile`, or merged into yours |
| `apparmor/rerouted` | An AppArmor profile confining rerouted to its settings, data directory, and network, for Debian and Ubuntu | `/etc/apparmor.d/rerouted` |
| `selinux/rerouted.te`, `.fc`, `.if` | An SELinux policy module doing the same, for Fedora, RHEL, and their relatives, with rerouted-keyd's, rerouted-sfu's, and rerouted-egress's domains | Built into `rerouted.pp`, then `semodule -i` |
| `rerouted-keyd.socket`, `rerouted-keyd.service`, `rerouted.service.d/keyd.conf` | Optional: rerouted-keyd holds the server keys in a process of its own, with no network, and signs for rerouted, which never has them | `/etc/systemd/system/`, keeping the names |
| `rerouted-keyd-seal.service`, `rerouted-keyd-seal` | Keep rerouted-keyd's keys encrypted with `systemd-creds`, and move the keys from rerouted's data directory the first time | `/etc/systemd/system/rerouted-keyd-seal.service`, `/usr/local/libexec/rerouted-keyd-seal` |
| `apparmor/rerouted-keyd` | The AppArmor profile for rerouted-keyd | `/etc/apparmor.d/rerouted-keyd` |
| `rerouted-sfu.socket`, `rerouted-sfu.service`, `rerouted.service.d/sfu.conf` | Optional: rerouted-sfu runs voice channels' SFU, with its UDP and WebRTC, in a process with no keys, data, or settings, that can't send to this host or link-local addresses | `/etc/systemd/system/`, keeping the names |
| `apparmor/rerouted-sfu` | The AppArmor profile for rerouted-sfu | `/etc/apparmor.d/rerouted-sfu` |
| `rerouted.socket`, `rerouted-egress.socket`, `rerouted-egress.service`, `rerouted.service.d/egress.conf` | Optional: rerouted runs without a network. systemd passes it its listening socket, and rerouted-egress makes its connections out, only where its own policy allows | `/etc/systemd/system/`, keeping the names |
| `apparmor/rerouted-egress` | The AppArmor profile for rerouted-egress | `/etc/apparmor.d/rerouted-egress` |
| `turnserver.conf.example` | coturn as the call relay, refusing to relay into private networks | `/etc/turnserver.conf` |

Each one uses `chat.example` as the domain and uppercase placeholders, such as `HOST_IP`, for values you fill in.
