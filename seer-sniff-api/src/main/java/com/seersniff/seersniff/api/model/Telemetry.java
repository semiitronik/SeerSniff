package com.seersniff.seersniff.api.model;

/**
 * Telemetry DTO sent from the sensor/sniffer.
 */
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