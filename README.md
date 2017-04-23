# vpnmcast

https://blog.danman.eu/multicast-over-stupid-networks/

## Installation
```
git clone https://github.com/danielkucera/vpnmcast.git /opt/vpnmcast
```
edit vpnmcast.py values:
```
sourceif = "tun1"  ## interface where do we source multicasts (send IGMP joins)
destifs = ["tap0"] ## array of interfaces where do we send multicasts to (receive IGMP joins)
```
```
ln -s /opt/vpnmcast/vpnmcast.service /etc/systemd/system/vpnmcast.service
systemctl daemon-reload
```

## Running

* you can run it directly:
```
/opt/vpnmcast/vpnmcast.py
```
* or as a systemd service:
```
systemctl enable vpnmcast
systemctl start vpnmcast
```
