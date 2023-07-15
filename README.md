# lls
*list of listening sockets for humans*

### Output sample

```plain
sshd (pid 836 user root) / :22 tcp / 0.0.0.0 + ::
systemd-resolve (pid 623 user systemd-resolve)
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
.kdeconnectd-wr (pid 1245 user k900)
├ :1716 tcp / *
└ :1716 udp / *
avahi-daemon (pid 655 user avahi)
├ :5353 udp / 0.0.0.0 + ::
├ :39826 udp / 0.0.0.0
└ :49528 udp / ::
```

### Why

`ss` is a powerful tool, but it not very good for my use-case:
 * Parameters. Is `-loptun` a good combination? I don't know.
 * Output for one socket may be broken into multiple lines.
 * Related sockets aren't always grouped together.
 * The command name isn't helpful when it's `python` or `node`.
 * The listening address isn't helpful with v6 addresses.

`lls` aims to do better:
 * No command line parameters necessary
 * Compact output (but hopefully not an eyesore)
 * Grouping sockets by process and port
 * Conservative command line parsing to show script names for interpreters
 * Pair listening addresses with interface names
