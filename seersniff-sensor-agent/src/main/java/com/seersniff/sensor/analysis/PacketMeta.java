package com.seersniff.sensor.analysis;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;

/**
 * Minimal metadata extracted from a pcap4j Packet.
 * Used by analyzer + API summaries (safe fields only).
 */
public class PacketMeta {

    public final boolean isIpv4;
    public final boolean isTcp;
    public final boolean isUdp;
    public final boolean isIcmp;

    public final String srcIp;
    public final String dstIp;

    public final Integer srcPort; // null for non-TCP/UDP
    public final Integer dstPort; // null for non-TCP/UDP

    public final int length;      // best-effort packet length

    private PacketMeta(
            boolean isIpv4,
            boolean isTcp,
            boolean isUdp,
            boolean isIcmp,
            String srcIp,
            String dstIp,
            Integer srcPort,
            Integer dstPort,
            int length
    ) {
        this.isIpv4 = isIpv4;
        this.isTcp = isTcp;
        this.isUdp = isUdp;
        this.isIcmp = isIcmp;
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.length = length;
    }

    public static PacketMeta from(Packet packet) {
        if (packet == null) {
            return new PacketMeta(false, false, false, false,
                    null, null, null, null, 0);
        }

        int len = safeLength(packet);

        // Only parsing IPv4 here (matches your current rules style)
        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 == null) {
            return new PacketMeta(false, false, false, false,
                    null, null, null, null, len);
        }

        String src = null;
        String dst = null;

        try {
            src = ipv4.getHeader().getSrcAddr().getHostAddress();
            dst = ipv4.getHeader().getDstAddr().getHostAddress();
        } catch (Exception ignored) { }

        // Determine L4 protocol from IPv4 header
        IpNumber proto = null;
        try {
            proto = ipv4.getHeader().getProtocol();
        } catch (Exception ignored) { }

        boolean tcp = false;
        boolean udp = false;
        boolean icmp = false;

        Integer sport = null;
        Integer dport = null;

        // Prefer direct packet type checks (robust)
        TcpPacket t = packet.get(TcpPacket.class);
        if (t != null) {
            tcp = true;
            sport = unsignedShort(t.getHeader().getSrcPort().value());
            dport = unsignedShort(t.getHeader().getDstPort().value());
        }

        UdpPacket u = packet.get(UdpPacket.class);
        if (u != null) {
            udp = true;
            sport = unsignedShort(u.getHeader().getSrcPort().value());
            dport = unsignedShort(u.getHeader().getDstPort().value());
        }

        // ICMPv4 detection:
        // pcap4j represents it as IcmpV4CommonPacket for most ICMPv4 messages.
        IcmpV4CommonPacket ic = packet.get(IcmpV4CommonPacket.class);
        if (ic != null) {
            icmp = true;
        } else {
            // fallback: sometimes payload detection is odd — use IPv4 protocol number if present
            if (proto != null && proto.equals(IpNumber.ICMPV4)) {
                icmp = true;
            }
        }

        return new PacketMeta(true, tcp, udp, icmp, src, dst, sport, dport, len);
    }

    private static int safeLength(Packet packet) {
        try {
            // pcap4j Packet has length()
            return packet.length();
        } catch (Exception ignored) {
            try {
                // fallback
                return packet.getRawData() != null ? packet.getRawData().length : 0;
            } catch (Exception ignored2) {
                return 0;
            }
        }
    }

    private static int unsignedShort(short s) {
        return s & 0xFFFF;
    }
}