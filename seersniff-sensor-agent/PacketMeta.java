package com.seersniff.sensor.analysis;

import org.pcap4j.packet.*;

public class PacketMeta {

    public final boolean isIpv4;
    public final boolean isTcp;
    public final boolean isUdp;
    public final boolean isIcmp;

    // TCP flags
    public final boolean syn;
    public final boolean ack;
    public final boolean fin;
    public final boolean rst;
    public final boolean psh;
    public final boolean urg;

    public final String srcIp;
    public final String dstIp;

    public final Integer srcPort;
    public final Integer dstPort;

    public final int length;

    private PacketMeta(
            boolean isIpv4,
            boolean isTcp,
            boolean isUdp,
            boolean isIcmp,
            boolean syn,
            boolean ack,
            boolean fin,
            boolean rst,
            boolean psh,
            boolean urg,
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

        this.syn = syn;
        this.ack = ack;
        this.fin = fin;
        this.rst = rst;
        this.psh = psh;
        this.urg = urg;

        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.length = length;
    }

    public static PacketMeta from(Packet packet) {

        if (packet == null) {
            return new PacketMeta(false,false,false,false,
                    false,false,false,false,false,false,
                    null,null,null,null,0);
        }

        int len = packet.length();

        IpV4Packet ipv4 = packet.get(IpV4Packet.class);
        if (ipv4 == null) {
            return new PacketMeta(false,false,false,false,
                    false,false,false,false,false,false,
                    null,null,null,null,len);
        }

        String src = ipv4.getHeader().getSrcAddr().getHostAddress();
        String dst = ipv4.getHeader().getDstAddr().getHostAddress();

        boolean tcp = false;
        boolean udp = false;
        boolean icmp = false;

        boolean syn = false;
        boolean ack = false;
        boolean fin = false;
        boolean rst = false;
        boolean psh = false;
        boolean urg = false;

        Integer sport = null;
        Integer dport = null;

        TcpPacket t = packet.get(TcpPacket.class);
        if (t != null) {
            tcp = true;
            var h = t.getHeader();
            syn = h.getSyn();
            ack = h.getAck();
            fin = h.getFin();
            rst = h.getRst();
            psh = h.getPsh();
            urg = h.getUrg();

            sport = h.getSrcPort().value() & 0xFFFF;
            dport = h.getDstPort().value() & 0xFFFF;
        }

        UdpPacket u = packet.get(UdpPacket.class);
        if (u != null) {
            udp = true;
            sport = u.getHeader().getSrcPort().value() & 0xFFFF;
            dport = u.getHeader().getDstPort().value() & 0xFFFF;
        }

        IcmpV4CommonPacket ic = packet.get(IcmpV4CommonPacket.class);
        if (ic != null) {
            icmp = true;
        }

        return new PacketMeta(
                true,
                tcp,
                udp,
                icmp,
                syn,
                ack,
                fin,
                rst,
                psh,
                urg,
                src,
                dst,
                sport,
                dport,
                len
        );
    }
}