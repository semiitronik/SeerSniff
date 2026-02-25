package com.first.src.analysis;

import java.util.ArrayDeque;
import java.util.Deque;

public class AnalysisContext {
    // Rolling window for ICMP burst detection
    private final Deque<Long> recentIcmpTimestamps = new ArrayDeque<>();

    public Deque<Long> getRecentIcmpTimestamps() {
        return recentIcmpTimestamps;
    }
}
