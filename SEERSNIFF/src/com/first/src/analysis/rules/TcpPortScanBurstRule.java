package com.first.src.analysis.rules;

import com.first.src.analysis.*;
import org.pcap4j.packet.Packet;

import java.util.List;
import java.util.Map;

public class TcpPortScanBurstRule implements SuspicionRule {

    private final int uniquePortThreshold;  // e.g., 20
    private final long windowMillis;        // e.g., 4 seconds

    public TcpPortScanBurstRule() { this(20, 4_000); }
    public TcpPortScanBurstRule(int uniquePortThreshold, long windowMillis) {
        this.uniquePortThreshold = uniquePortThreshold;
        this.windowMillis = windowMillis;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        PacketMeta m = PacketMeta.from(packet);
        if (!m.isTcp || !m.isIpv4 || m.srcIp == null || m.dstPort == null) return 0;

        // Track SYN attempts (SYN without ACK is the typical scan probe)
        if (!(m.syn && !m.ack)) return 0;

        long now = ctx.getCurrentPacketTime();

        // window maintenance
        ctx.synTimeWindow(m.srcIp).addLast(now);
        AnalysisContext.evictOld(ctx.synTimeWindow(m.srcIp), now, windowMillis);

        Map<Integer, Long> ports = ctx.synPortsWindow(m.srcIp);
        ports.put(m.dstPort, now);
        AnalysisContext.evictOld(ports, now, windowMillis);

        int uniquePorts = ports.size();
        if (uniquePorts < uniquePortThreshold) return 0;

        // Strong score because it’s pattern-based
        // 20 ports -> 55, 40 ports -> 75 (cap 85)
        int over = uniquePorts - uniquePortThreshold;
        return Math.min(85, 55 + (over / 5) * 5);
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        PacketMeta m = PacketMeta.from(packet);
        if (m.srcIp == null) return;
        int uniquePorts = ctx.synPortsWindow(m.srcIp).size();
        outReasons.add("Possible TCP port scan: " + uniquePorts + " unique destination ports probed by " + m.srcIp + " in a short window.");
    }
}