package com.seersniff.sensor.analysis;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.HashMap;

public class PacketAnalyzer {

    private final List<SuspicionRule> rules;

    public PacketAnalyzer(List<SuspicionRule> rules) {
        if (rules == null) {
            throw new IllegalArgumentException("rules cannot be null");
        }
        this.rules = new ArrayList<>(rules); // defensive copy
    }

    /**
     * Returns an unmodifiable view of the configured rules.
     * Prevents outside mutation.
     */
    public List<SuspicionRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    public SuspicionResult analyze(Packet packet) {

        AnalysisContext ctx = new AnalysisContext();
        List<String> reasons = new ArrayList<>();
        Map<String, Integer> ruleScores = new HashMap<>();

        int totalScore = 0;

        for (SuspicionRule rule : rules) {

            int score = rule.score(packet, ctx);

            if (score > 0) {
                totalScore += score;
                ruleScores.put(rule.getClass().getSimpleName(), score);
                rule.explain(packet, ctx, reasons);
            }
        }

        Severity severity = mapSeverity(totalScore);

        return new SuspicionResult(
                totalScore,
                severity,
                reasons,
                ruleScores
        );
    }

    private Severity mapSeverity(int score) {
        if (score >= 80) return Severity.HIGH;
        if (score >= 40) return Severity.MEDIUM;
        return Severity.LOW;
    }
}