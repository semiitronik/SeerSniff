package com.first.src.analysis.rules;

import com.first.src.analysis.*;
import org.pcap4j.packet.Packet;

import java.util.List;

public class TcpRstBurstRule implements SuspicionRule {

    private final int threshold;     // e.g., 25
    private final long windowMillis; // e.g., 5 seconds

    public TcpRstBurstRule() { this(25, 5_000); }
    public TcpRstBurstRule(int threshold, long windowMillis) {
        this.threshold = threshold;
        this.windowMillis = windowMillis;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        PacketMeta m = PacketMeta.from(packet);
        if (!m.isTcp || !m.isIpv4 || m.srcIp == null) return 0;

        if (!m.rst) return 0;

        long now = ctx.getCurrentPacketTime();
        var q = ctx.rstWindow(m.srcIp);
        q.addLast(now);
        AnalysisContext.evictOld(q, now, windowMillis);

        int c = q.size();
        if (c < threshold) return 0;

        // Moderate-strong (RST bursts can happen, but sustained bursts are suspicious)
        return Math.min(70, 40 + (c - threshold));
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        PacketMeta m = PacketMeta.from(packet);
        if (m.srcIp == null) return;
        outReasons.add("High TCP RST rate from " + m.srcIp + " (often seen during scanning or repeated failed connections).");
    }
}
