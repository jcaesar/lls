# lls
*list of listening sockets for humans*

### Output sample

```plain
sshd (pid 836 user root) / :22 tcp / 0.0.0.0 + ::
systemd-resolved (pid 623 user systemd-resolve)
├ :53 tcp
│ ├ 127.0.0.53 (lo)
│ └ 127.0.0.54 (lo)
├ :53 udp
│ ├ 127.0.0.53 (lo)
│ └ 127.0.0.54 (lo)
├ :5355 tcp / 0.0.0.0 + ::
└ :5355 udp / 0.0.0.0 + ::
NetworkManager (pid 733 user root)
├ :58 raw / *
└ :546 udp / fe80::eb32:98c3:7108:525d (wlan0)
systemd (pid 1 user root) / :631 tcp / 127.0.0.1 (lo)
cupsd (pid 866 user root) / :631 tcp / ::1 (lo)
kdeconnectd (pid 1245 user k900)
├ :1716 tcp / *
└ :1716 udp / *
avahi-daemon (pid 655 user avahi)
├ :5353 udp / 0.0.0.0 + ::
├ :39826 udp / 0.0.0.0
└ :49528 udp / ::
```

### Why

`lls` selling points:
 * Requiring no parameters
 * Having a compact output format
 * Grouping output by process and port
 * Summarizing script interpreter command lines
 * Showing interface names for listening addresses
 * Explaining wireguard and vxlan listening ports

More specifically
 * `ss` has a nice short command, but then you need a lot of arguments. But which? `-lpunt`? (Though of course, `ss` can do things `lls` can't, like printing established connections or unix sockets.)
 * `ss` output requires ~160 columns, while `lls` makes do with ~60.
 * `ss` output order is unfathomable.
 * For interpreters, `ss` will just display the command name, e.g. `python` or `node`.
   `lls` tries to parse the command line of the interpreters and display the script name where possible.
 * `ss` prints almost no information for listening ports belonging to WireGuard or VXLAN interfaces, and what it prints is more confusing than helpful.
