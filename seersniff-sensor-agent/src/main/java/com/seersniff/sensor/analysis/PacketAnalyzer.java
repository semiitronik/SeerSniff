package com.seersniff.sensor.analysis;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Fixed PacketAnalyzer: reuses a single AnalysisContext so window-based rules
 * (ICMP/TCP/UDP burst detectors) can accumulate events across packets.
 *
 * Also provides safer rule execution and correlation bonus logic.
 */
public class PacketAnalyzer {

    private final List<SuspicionRule> rules;
    private final AnalysisContext context;

    public PacketAnalyzer(List<SuspicionRule> rules) {
        this.rules = (rules == null) ? List.of() : List.copyOf(rules);
        this.context = new AnalysisContext();
    }

    /**
     * Live/default analysis (uses wall-clock time).
     * Good for live capture.
     */
    public SuspicionResult analyze(Packet packet) {
        return analyze(packet, System.currentTimeMillis());
    }

    /**
     * Deterministic analysis using a caller-provided packet timestamp (ms).
     * Useful for testing / pcap replay.
     */
    public SuspicionResult analyze(Packet packet, long packetTimeMillis) {
        if (packet == null) return SuspicionResult.clean();

        // Set 'now' for burst/window rules
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

        // Optional correlation bonus: scan burst + high-risk port increases confidence
        boolean scanBurst = reasons.stream().anyMatch(r -> r.toLowerCase().contains("port scan") || r.toLowerCase().contains("port scan burst"));
        boolean highRiskPort = reasons.stream().anyMatch(r ->
                r.contains("445") || r.contains("3389") || r.toLowerCase().contains("telnet"));

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
        try {
            return rule.score(packet, context);
        } catch (Exception e) {
            System.err.println("[PacketAnalyzer] rule.score() threw for " + rule.getClass().getSimpleName() + ": " + e.getMessage());
            return 0;
        }
    }

    private void safeExplain(SuspicionRule rule, Packet packet, List<String> reasons) {
        try {
            rule.explain(packet, context, reasons);
        } catch (Exception e) {
            System.err.println("[PacketAnalyzer] rule.explain() threw for " + rule.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }
}