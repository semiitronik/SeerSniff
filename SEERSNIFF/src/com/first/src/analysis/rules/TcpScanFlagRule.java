package com.first.src.analysis.rules;

import com.first.src.analysis.AnalysisContext;
import com.first.src.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.List;

public class TcpScanFlagRule implements SuspicionRule {

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp == null) return 0;

        TcpPacket.TcpHeader h = tcp.getHeader();

        boolean syn = h.getSyn();
        boolean ack = h.getAck();
        boolean fin = h.getFin();
        boolean rst = h.getRst();
        boolean psh = h.getPsh();
        boolean urg = h.getUrg();

        // SYN without ACK can be normal; keep moderate weight
        if (syn && !ack && !fin && !rst) return 5;

        // NULL scan: no flags set
        if (!syn && !ack && !fin && !rst && !psh && !urg) return 45;

        // FIN-only scan
        if (fin && !syn && !ack && !rst && !psh && !urg) return 45;

        // Xmas scan: FIN+PSH+URG
        if (fin && psh && urg) return 60;

        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp == null) return;

        TcpPacket.TcpHeader h = tcp.getHeader();

        boolean syn = h.getSyn();
        boolean ack = h.getAck();
        boolean fin = h.getFin();
        boolean rst = h.getRst();
        boolean psh = h.getPsh();
        boolean urg = h.getUrg();

        if (syn && !ack && !fin && !rst) outReasons.add("TCP SYN without ACK (could be normal scan/connection attempt).");
        else if (!syn && !ack && !fin && !rst && !psh && !urg) outReasons.add("TCP NULL flags pattern (scan-like).");
        else if (fin && !syn && !ack && !rst && !psh && !urg) outReasons.add("TCP FIN-only pattern (scan-like).");
        else if (fin && psh && urg) outReasons.add("TCP Xmas flags pattern (scan-like).");
    }
}