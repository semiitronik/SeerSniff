package com.first.src.analysis;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.List;

public class PacketAnalyzer {

    private final List<SuspicionRule> rules;
    private final AnalysisContext context;

    public PacketAnalyzer(List<SuspicionRule> rules) {
        this.rules = (rules == null) ? List.of() : List.copyOf(rules);
        this.context = new AnalysisContext();
    }

    public SuspicionResult analyze(Packet packet) {
        if (packet == null) return SuspicionResult.clean();

        int total = 0;
        List<String> reasons = new ArrayList<>();

        for (SuspicionRule rule : rules) {
            int s = safeScore(rule, packet);
            if (s > 0) {
                total += s;
                safeExplain(rule, packet, reasons);
            }
        }

        int finalScore = Math.min(total, 100);
        Severity sev = (finalScore >= 70) ? Severity.HIGH
                : (finalScore >= 35) ? Severity.MEDIUM
                : Severity.LOW;

        return new SuspicionResult(finalScore, sev, reasons);
    }

    public AnalysisContext getContext() {
        return context;
    }

    private int safeScore(SuspicionRule rule, Packet packet) {
        try { return rule.score(packet, context); }
        catch (Exception ignored) { return 0; }
    }

    private void safeExplain(SuspicionRule rule, Packet packet, List<String> reasons) {
        try { rule.explain(packet, context, reasons); }
        catch (Exception ignored) { }
    }
}