package com.seersniff.seersniff.api.model;

import java.util.List;
import java.util.Map;

public record AlertEvent(
        String sensorId,
        long ts,

        // optional packet meta (can be null for now)
        String srcIp,
        String dstIp,
        Integer srcPort,
        Integer dstPort,
        String protocol,

        int score,
        String severity,

        // ✅ what your UI expects
        String summary,

        List<String> reasons,
        Map<String, Integer> ruleScores
) {}