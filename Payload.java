package com.first.src.analysis.rules;

import com.first.src.analysis.AnalysisContext;
import com.first.src.analysis.SuspicionRule;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.Packet;

import java.util.Deque;
import java.util.List;

public class IcmpBurstRule implements SuspicionRule {

    private final int thresholdCount; // e.g., 20
    private final long windowMillis;  // e.g., 5 seconds

    public IcmpBurstRule() {
        this(20, 5_000);
    }

    public IcmpBurstRule(int thresholdCount, long windowMillis) {
        this.thresholdCount = thresholdCount;
        this.windowMillis = windowMillis;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        if (icmp == null) return 0;

        long now = System.currentTimeMillis();
        Deque<Long> q = ctx.getRecentIcmpTimestamps();
        q.addLast(now);

        while (!q.isEmpty() && (now - q.peekFirst()) > windowMillis) {
            q.removeFirst();
        }

        if (q.size() >= thresholdCount) return 50;
        return 0;
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        outReasons.add("High ICMP rate detected (possible recon/flood burst).");
    }
}