package com.first.src.analysis;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class PacketAnalyzer {

    private final List<SuspicionRule> rules;
    private final AnalysisContext context;

    public PacketAnalyzer(List<SuspicionRule> rules) {
        this.rules = (rules == null) ? List.of() : List.copyOf(rules);
        this.context = new AnalysisContext();
    }

    /**
     * Live/default analysis (wall-clock time).
     * Good for live capture, but NOT ideal for PCAP replay reproducibility.
     */
    public SuspicionResult analyze(Packet packet) {
        return analyze(packet, System.currentTimeMillis());
    }

    /**
     * Deterministic analysis using a caller-provided packet timestamp (ms).
     * Use this for PCAP replay and synthetic experiments.
     */
    public SuspicionResult analyze(Packet packet, long packetTimeMillis) {
        if (packet == null) return SuspicionResult.clean();

        // ✅ Critical: set the "current packet time" for burst/window-based rules
        context.setCurrentPacketTime(packetTimeMillis);

        int total = 0;
        List<String> reasons = new ArrayList<>();
        Map<String, Integer> contributions = new LinkedHashMap<>();

        for (SuspicionRule rule : rules) {
            int s = safeScore(rule, packet);
            if (s > 0) {
                total += s;
                contributions.merge(rule.getClass().getSimpleName(), s, Integer::sum);
                safeExplain(rule, packet, reasons);
            }
        }

        // Simple correlation bonus (kept intentionally transparent for research)
        boolean scanBurst = reasons.stream().anyMatch(s -> s.toLowerCase().contains("port scan"));
        boolean highRiskPort = reasons.stream().anyMatch(s ->
                s.contains("445") || s.contains("3389") || s.toLowerCase().contains("telnet"));

        int bonus = 0;
        if (scanBurst && highRiskPort) bonus = 10;
        if (bonus > 0) {
            total += bonus;
            contributions.put("CorrelationBonus", bonus);
            reasons.add("Correlation: scan burst + high-risk service targeting increases confidence.");
        }

        int finalScore = Math.min(total, 100);
        Severity sev = (finalScore >= 70) ? Severity.HIGH
                : (finalScore >= 45) ? Severity.MEDIUM
                : Severity.LOW;

        return new SuspicionResult(finalScore, sev, reasons, contributions);
    }

    public AnalysisContext getContext() {
        return context;
    }

    /** Exposes the active rules (useful for exports / experiment reports). */
    public List<SuspicionRule> getRules() {
        return rules;
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