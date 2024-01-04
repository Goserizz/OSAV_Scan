# DNSRoute

# 简介
DNSRoute使用Traceroute的方法，探测DNS报文到目标IP的。与Traceroute不同的是，如果目标IP是一个透明转发服务器，DNSRoute可以探测到目标IP到透明转发目的IP的路径，为透明转发场景提供详细的信息以供分析。

## Build
```shell
go build -o dnsroute
```
因为监听所有ICMP报文需要root权限，如果想在用户权限下运行dnsroute，需要先提升dnsroute的网络权限
```shell
sudo setcap cap_net_raw+ep dnsroute
```
本目录下的dnsroute程序是在linux amd64下打包的程序。

## Usage
```
dnsroute [-eips] <target_ip>
    -e <End TTL>    (default 40)
    -i <Interface>  (default default route)
    -p <Local Port> (default 16657)
    -s <Start TTL>  (default 1)
```

## Example
```
> dnsroute 168.0.65.17 
2024/01/04 10:42:32 Using interface eth0: 192.168.1.63#16657 to DNSRoute 168.0.65.17#53 with TTL from 1 to 40
2024/01/04 10:42:32 TTL = 1, RTT = 0 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 11.209.114.34
2024/01/04 10:42:33 TTL = 2, RTT = 10 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 11.73.4.57
2024/01/04 10:42:34 TTL = 3, RTT = 0 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 10.54.182.110
2024/01/04 10:42:35 TTL = 4, RTT = 1 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 116.251.118.130
2024/01/04 10:42:36 TTL = 5, RTT = 1 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 116.251.119.138
2024/01/04 10:42:37 TTL = 6
2024/01/04 10:42:38 TTL = 7, RTT = 4 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 119.6.197.49
2024/01/04 10:42:39 TTL = 8
2024/01/04 10:42:40 TTL = 9, RTT = 45 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 219.158.18.70
2024/01/04 10:42:41 TTL = 10, RTT = 40 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 219.158.16.82
2024/01/04 10:42:42 TTL = 11, RTT = 183 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 219.158.16.98
2024/01/04 10:42:43 TTL = 12
2024/01/04 10:42:44 TTL = 13, RTT = 334 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 200.189.231.5
2024/01/04 10:42:45 TTL = 14, RTT = 333 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 8.243.50.82
2024/01/04 10:42:46 TTL = 15
2024/01/04 10:42:47 TTL = 16, RTT = 332 ms: Recieve ICMP (icmp-ip-dst = 168.0.65.17) from 168.0.65.17
2024/01/04 10:42:48 TTL = 17
2024/01/04 10:42:49 TTL = 18
2024/01/04 10:42:50 TTL = 19
2024/01/04 10:42:51 TTL = 20, RTT = 380 ms: Recieve ICMP (icmp-ip-dst = 1.1.1.1) from 187.16.219.111
2024/01/04 10:42:52 TTL = 21, RTT = 373 ms: Recieve ICMP (icmp-ip-dst = 1.1.1.1) from 172.71.15.2
2024/01/04 10:42:53 TTL = 22
2024/01/04 10:42:54 TTL = 23
2024/01/04 10:42:55 TTL = 24, RTT = 582 ms: Receive DNS response from 1.1.1.1:53
```