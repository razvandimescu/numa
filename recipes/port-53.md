# Freeing port 53

Numa binds `0.0.0.0:53` to be the system resolver. On most Linux desktops something already owns that port, and Numa will not stop or reconfigure another resolver for you. This recipe covers the common holders.

Find out which one you have:

```bash
sudo ss -lnup 'sport = :53'     # Linux
sudo lsof -nP -iUDP:53          # macOS
```

Numa names the holder itself when it fails to bind, including the systemd unit that started it.

## systemd-resolved

The only case Numa handles for you. `sudo numa install` writes `/etc/systemd/resolved.conf.d/numa.conf` with `DNSStubListener=no`, restarts resolved, and takes the port. Nothing to do here.

## dnsmasq, standalone

```bash
sudo systemctl disable --now dnsmasq.service
sudo numa install
```

## dnsmasq, started by NetworkManager

The case in [issue #299](https://github.com/razvandimescu/numa/issues/299). `systemctl disable dnsmasq` does not help and neither does killing the process: NetworkManager runs its own dnsmasq instance and restarts it. Turn off NetworkManager's DNS cache instead.

Check whether this is your setup:

```bash
grep -r '^dns=' /etc/NetworkManager/    # dns=dnsmasq means NetworkManager owns it
```

Then:

```bash
sudo tee /etc/NetworkManager/conf.d/00-numa.conf >/dev/null <<'EOF'
[main]
dns=none
EOF

sudo systemctl restart NetworkManager
sudo numa install
```

`dns=none` stops NetworkManager from spawning dnsmasq and from managing `/etc/resolv.conf`, leaving `numa install` free to point it at 127.0.0.1. To keep NetworkManager in charge of resolv.conf instead, use `dns=default` and pin the connection's DNS so DHCP does not overwrite it:

```bash
nmcli con mod "<connection>" ipv4.dns 127.0.0.1 ipv4.ignore-auto-dns yes
```

To undo: `sudo rm /etc/NetworkManager/conf.d/00-numa.conf && sudo systemctl restart NetworkManager`.

## unbound, named, pihole-FTL

Same shape as standalone dnsmasq. Stop the service, then install:

```bash
sudo systemctl disable --now unbound.service     # or named.service, pihole-FTL.service
sudo numa install
```

Pi-hole is worth a moment's thought before you disable it: Numa's `[blocking]` section covers the same ground, so this is a replacement rather than a coexistence.

## Running alongside, without taking port 53

For testing, or when the existing resolver has to stay, put Numa on a spare port:

```bash
numa config edit    # [server] bind_addr = "127.0.0.1:5354"
numa
dig @127.0.0.1 -p 5354 example.com
```

Nothing else on the machine will use it until you point clients at that address, and `numa install` is not involved.

## Verifying

```bash
sudo numa install
numa service status     # active (running), not activating (auto-restart) or failed
dig @127.0.0.1 example.com
```

If `numa service status` shows the service restarting in a loop, port 53 is still held. `journalctl -u numa -n 20` prints the same advisory with the holder named.
