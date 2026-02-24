package com.seersniff.sensor.analysis;

import java.util.Collections;
import java.util.List;
import java.util.Map;

public class SuspicionResult {
    private final int score;
    private final Severity severity;
    private final List<String> reasons;
    private final Map<String, Integer> ruleScores;

    public SuspicionResult(int score, Severity severity, List<String> reasons, Map<String, Integer> ruleScores) {
        this.score = score;
        this.severity = severity;
        this.reasons = reasons == null ? List.of() : List.copyOf(reasons);
        this.ruleScores = ruleScores == null ? Map.of() : Map.copyOf(ruleScores);
    }

    public static SuspicionResult clean() {
        return new SuspicionResult(0, Severity.LOW, Collections.emptyList(), Collections.emptyMap());
    }

    public int getScore() { return score; }
    public Severity getSeverity() { return severity; }
    public List<String> getReasons() { return reasons; }
    public Map<String, Integer> getRuleScores() { return ruleScores; }
}