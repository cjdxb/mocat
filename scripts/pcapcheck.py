#!/usr/bin/env python3
"""分析节点出口抓包：检查每条流的第一个有载荷报文是否为伪装报文（验收标准 5/6/7）。

用法: pcapcheck.py <pcap> <目标IP> <tcp|udp> <目标端口> <expect: fake|plain> [fake_ttl] [marker]
  fake : 每条流都必须先出现伪装报文（TTL == fake_ttl 且载荷包含 marker），且之前没有真实载荷
  plain: 不允许出现任何伪装报文
输出 JSON 摘要；违反时退出码 1。
"""
import json
import socket
import struct
import sys


def packets(path):
    with open(path, "rb") as f:
        gh = f.read(24)
        magic = struct.unpack("<I", gh[:4])[0]
        endian = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            h = f.read(16)
            if len(h) < 16:
                return
            _, _, incl, _ = struct.unpack(endian + "IIII", h)
            data = f.read(incl)
            if linktype == 1:  # Ethernet
                if len(data) < 14 or data[12:14] != b"\x08\x00":
                    continue
                data = data[14:]
            elif linktype == 113:  # Linux cooked
                if data[14:16] != b"\x08\x00":
                    continue
                data = data[16:]
            yield data


def main():
    path, dst, proto, dport, expect = sys.argv[1:6]
    fake_ttl = int(sys.argv[6]) if len(sys.argv) > 6 else 1
    marker = sys.argv[7].encode() if len(sys.argv) > 7 else b""
    dport = int(dport)
    flows = {}
    for ip in packets(path):
        ihl = (ip[0] & 0xF) * 4
        total = struct.unpack("!H", ip[2:4])[0]
        ttl, p = ip[8], ip[9]
        src, d = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
        if d != dst:
            continue
        l4 = ip[ihl:total]
        if proto == "tcp" and p == 6:
            sport, dp = struct.unpack("!HH", l4[:4])
            payload = l4[(l4[12] >> 4) * 4:]
        elif proto == "udp" and p == 17:
            sport, dp = struct.unpack("!HH", l4[:4])
            payload = l4[8:]
        else:
            continue
        if dp != dport or not payload:
            continue
        flows.setdefault((src, sport), []).append((ttl, payload))

    problems, summary = [], []
    for key, pkts in flows.items():
        fakes = [t for t, pl in pkts if t == fake_ttl]
        real = [t for t, pl in pkts if t != fake_ttl]
        first_ttl = pkts[0][0]
        summary.append({"flow": f"{key[0]}:{key[1]}", "first_ttl": first_ttl, "fake": len(fakes), "real": len(real)})
        if expect == "fake":
            if first_ttl != fake_ttl:
                problems.append(f"{key}: 第一个有载荷的报文 TTL={first_ttl}，不是伪装报文")
            elif marker and marker not in pkts[0][1]:
                problems.append(f"{key}: 伪装报文载荷中没有 {marker!r}")
        elif fakes:
            problems.append(f"{key}: 不应出现伪装报文")
    print(json.dumps({"flows": len(flows), "problems": problems, "detail": summary}, ensure_ascii=False))
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
