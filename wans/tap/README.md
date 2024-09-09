# Linux tun/tap WAN driver

## TUN Requirements
- IPv4 forwarding is enabled
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

- Accept packets with local source addresses 
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/conf/all/accept_local
```

- Enable masquerading on default interface (i.e., eth0)
```bash
sudo nft add rule nat postrouting masquerade
```