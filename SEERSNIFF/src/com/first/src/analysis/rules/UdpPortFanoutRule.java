package com.first.src.analysis.rules;

import com.first.src.analysis.*;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.Map;

public class UdpPortFanoutRule implements SuspicionRule {

    private final int uniquePortThreshold;  // e.g., 30
    private final long windowMillis;        // e.g., 5 seconds

    public UdpPortFanoutRule() { this(30, 5_000); }
    public UdpPortFanoutRule(int uniquePortThreshold, long windowMillis) {
        this.uniquePortThreshold = uniquePortThreshold;
        this.windowMillis = windowMillis;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        PacketMeta m = PacketMeta.from(packet);
        if (!m.isUdp || !m.isIpv4 || m.srcIp == null || m.dstPort == null) return 0;

        long now = ctx.getCurrentPacketTime();
        ctx.udpTimeWindow(m.srcIp).addLast(now);
        AnalysisContext.evictOld(ctx.udpTimeWindow(m.srcIp), now, windowMillis);

        Map<Integer, Long> ports = ctx.udpPortsWindow(m.srcIp);
        ports.put(m.dstPort, now);
        AnalysisContext.evictOld(ports, now, windowMillis);

        int uniquePorts = ports.size();
        if (uniquePorts < uniquePortThreshold) return 0;

        return Math.min(80, 50 + (uniquePorts - uniquePortThreshold));
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        PacketMeta m = PacketMeta.from(packet);
        if (m.srcIp == null) return;
        outReasons.add("Possible UDP scan/fanout: many destination ports targeted by " + m.srcIp + " in a short window.");
    }
}