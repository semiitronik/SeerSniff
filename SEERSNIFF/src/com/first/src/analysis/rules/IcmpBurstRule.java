package com.first.src.analysis.rules;

import com.first.src.analysis.AnalysisContext;
import com.first.src.analysis.SuspicionRule;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IcmpV4Type;

import java.util.Deque;
import java.util.List;

public class IcmpBurstRule implements SuspicionRule {

    private final int thresholdCount; // e.g., 25
    private final long windowMillis;  // e.g., 5 seconds

    public IcmpBurstRule() {
        this(25, 5_000);
    }

    public IcmpBurstRule(int thresholdCount, long windowMillis) {
        this.thresholdCount = thresholdCount;
        this.windowMillis = windowMillis;
    }

    @Override
    public int score(Packet packet, AnalysisContext ctx) {
        IcmpV4CommonPacket icmp = packet.get(IcmpV4CommonPacket.class);
        IpV4Packet ip = packet.get(IpV4Packet.class);
        if (icmp == null || ip == null) return 0;

        // Only consider ICMP Echo requests (ping bursts)
        if (!IcmpV4Type.ECHO.equals(icmp.getHeader().getType())) return 0;

        String srcIp = ip.getHeader().getSrcAddr().getHostAddress();

        long now = ctx.getCurrentPacketTime();
        Deque<Long> q = ctx.icmpWindow(srcIp);
        q.addLast(now);

        while (!q.isEmpty() && (now - q.peekFirst()) > windowMillis) {
            q.removeFirst();
        }

        int c = q.size();
        if (c < thresholdCount) return 0;

        // Score increases with burst size (caps at 60)
        // threshold -> 35, bigger bursts -> 60
        int over = c - thresholdCount;
        return Math.min(60, 35 + (over / 5) * 5);
    }

    @Override
    public void explain(Packet packet, AnalysisContext ctx, List<String> outReasons) {
        IpV4Packet ip = packet.get(IpV4Packet.class);
        String srcIp = (ip == null) ? "unknown" : ip.getHeader().getSrcAddr().getHostAddress();
        outReasons.add("High ICMP Echo rate from " + srcIp + " (possible recon/flood burst).");
    }
}