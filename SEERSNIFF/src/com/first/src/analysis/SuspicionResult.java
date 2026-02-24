package com.first.src.analysis;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class SuspicionResult {
    private final int score;                 // 0-100
    private final Severity severity;
    private final List<String> reasons;

    // Optional: per-rule contribution breakdown (rule simple name -> points)
    private final Map<String, Integer> ruleScores;

    public SuspicionResult(int score, Severity severity, List<String> reasons) {
        this(score, severity, reasons, Collections.emptyMap());
    }

    public SuspicionResult(int score, Severity severity, List<String> reasons, Map<String, Integer> ruleScores) {
        this.score = clamp(score, 0, 100);
        this.severity = severity == null ? Severity.LOW : severity;
        this.reasons = reasons == null ? Collections.emptyList() : Collections.unmodifiableList(reasons);

        if (ruleScores == null || ruleScores.isEmpty()) {
            this.ruleScores = Collections.emptyMap();
        } else {
            // preserve insertion order for nicer UI/exports
            this.ruleScores = Collections.unmodifiableMap(new LinkedHashMap<>(ruleScores));
        }
    }

    public int getScore() { return score; }
    public Severity getSeverity() { return severity; }
    public List<String> getReasons() { return reasons; }

    /** Per-rule score contributions (may be empty). */
    public Map<String, Integer> getRuleScores() { return ruleScores; }

    public boolean isSuspicious() {
        return score >= 45; // tune threshold
    }

    public static SuspicionResult clean() {
        return new SuspicionResult(0, Severity.LOW, Collections.emptyList(), Collections.emptyMap());
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}
