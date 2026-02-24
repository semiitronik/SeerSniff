package com.first.src.analysis;

import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public class PacketMeta {
    public final String srcIp;
    public final String dstIp;
    public final Integer srcPort;
    public final Integer dstPort;
    public final boolean isTcp;
    public final boolean isUdp;
    public final boolean isIpv4;

    // TCP flags (valid only if isTcp)
    public final boolean syn, ack, fin, rst, psh, urg;

    public final int length;

    private PacketMeta(String srcIp, String dstIp, Integer srcPort, Integer dstPort,
                       boolean isTcp, boolean isUdp, boolean isIpv4,
                       boolean syn, boolean ack, boolean fin, boolean rst, boolean psh, boolean urg,
                       int length) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.isTcp = isTcp;
        this.isUdp = isUdp;
        this.isIpv4 = isIpv4;
        this.syn = syn; this.ack = ack; this.fin = fin; this.rst = rst; this.psh = psh; this.urg = urg;
        this.length = length;
    }

    public static PacketMeta from(Packet packet) {
        if (packet == null) return new PacketMeta(null, null, null, null,
                false, false, false, false, false, false, false, false, false, 0);

        IpV4Packet ip = packet.get(IpV4Packet.class);
        String srcIp = (ip != null) ? ip.getHeader().getSrcAddr().getHostAddress() : null;
        String dstIp = (ip != null) ? ip.getHeader().getDstAddr().getHostAddress() : null;

        TcpPacket tcp = packet.get(TcpPacket.class);
        UdpPacket udp = packet.get(UdpPacket.class);

        boolean isTcp = tcp != null;
        boolean isUdp = udp != null;
        Integer srcPort = isTcp ? tcp.getHeader().getSrcPort().valueAsInt() : (isUdp ? udp.getHeader().getSrcPort().valueAsInt() : null);
        Integer dstPort = isTcp ? tcp.getHeader().getDstPort().valueAsInt() : (isUdp ? udp.getHeader().getDstPort().valueAsInt() : null);

        boolean syn=false, ack=false, fin=false, rst=false, psh=false, urg=false;
        if (isTcp) {
            var h = tcp.getHeader();
            syn = h.getSyn(); ack = h.getAck(); fin = h.getFin(); rst = h.getRst(); psh = h.getPsh(); urg = h.getUrg();
        }

        return new PacketMeta(srcIp, dstIp, srcPort, dstPort, isTcp, isUdp, ip != null,
                syn, ack, fin, rst, psh, urg, packet.length());
    }
}
