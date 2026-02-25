package com.first.src.analysis.rules;

import com.first.src.analysis.AnalysisContext;
import com.first.src.analysis.SuspicionRule;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

import java.util.List;
import java.util.Set;

public class HighRiskPortRule implements SuspicionRule {

    private final Set<Integer> riskyPorts = Set.of(
            23,    // Telnet
            445,   // SMB
            3389,  // RDP
            1433,  // MSSQL
            5900,  // VNC
            22,    // SSH
            80, 443
    );

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        Integer dst = getDstPort(packet);
        if (dst == null) return 0;

        if (dst == 445 || dst == 3389 || dst == 23) return 35;
        if (riskyPorts.contains(dst)) return 15;
        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        Integer dst = getDstPort(packet);
        if (dst == null) return;

        if (dst == 445) outReasons.add("Destination port 445 (SMB) is frequently targeted/scanned.");
        else if (dst == 3389) outReasons.add("Destination port 3389 (RDP) is frequently targeted/scanned.");
        else if (dst == 23) outReasons.add("Destination port 23 (Telnet) is insecure and commonly targeted.");
        else outReasons.add("Destination port " + dst + " is commonly scanned/targeted.");
    }

    private Integer getDstPort(Packet packet) {
        TcpPacket tcp = packet.get(TcpPacket.class);
        if (tcp != null) return tcp.getHeader().getDstPort().valueAsInt();

        UdpPacket udp = packet.get(UdpPacket.class);
        if (udp != null) return udp.getHeader().getDstPort().valueAsInt();

        return null;
    }
}