package com.seersniff.sensor.net;

import java.util.List;
import java.util.Map;

public record IngestClient(
        String sensorId,
        long ts,
        String srcIp,
        String dstIp,
        Integer srcPort,
        Integer dstPort,
        String protocol,
        int score,
        String severity,
        String summary,
        List<String> reasons,
        Map<String, Integer> ruleScores
) {}