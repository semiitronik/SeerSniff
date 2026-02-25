package com.first.src.analysis;

import java.util.Collections;
import java.util.List;

public class SuspicionResult {
    private final int score;                 // 0-100
    private final Severity severity;
    private final List<String> reasons;

    public SuspicionResult(int score, Severity severity, List<String> reasons) {
        this.score = clamp(score, 0, 100);
        this.severity = severity == null ? Severity.LOW : severity;
        this.reasons = reasons == null ? Collections.emptyList() : Collections.unmodifiableList(reasons);
    }

    public int getScore() { return score; }
    public Severity getSeverity() { return severity; }
    public List<String> getReasons() { return reasons; }

    public boolean isSuspicious() {
        return score >= 35; // tune threshold
    }

    public static SuspicionResult clean() {
        return new SuspicionResult(0, Severity.LOW, Collections.emptyList());
    }

    private static int clamp(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }
}