package com.seersniff.sensor.net.dto;

public record Telemetry(
        String sensorId,
        long ts,
        boolean capturing,
        long packetsCaptured,
        long packetsDropped,
        double packetsPerSec,
        int activeFlows,
        int queueDepth
) {}