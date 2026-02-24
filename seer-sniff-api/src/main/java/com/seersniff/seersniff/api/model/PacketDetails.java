package com.seersniff.seersniff.api.model;

import java.util.List;
import java.util.Map;

public record PacketDetails(
        String sensorId,
        long ts,
        long packetId,
        int score,
        String severity,
        List<String> reasons,
        Map<String,Integer> ruleScores,
        String rawText
) {}