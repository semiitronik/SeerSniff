package com.seersniff.sensor.net.dto;

import java.util.List;
import java.util.Map;

public record AlertEvent(
        String sensorId,
        long ts,
        String severity,
        int score,
        String summary,
        List<String> reasons,
        Map<String, Integer> ruleScores
) {}