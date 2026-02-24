package com.seersniff.sensor.net.dto;

public record PacketSummary(
        String sensorId,
        long ts,
        long packetId,
        String srcIp,
        String dstIp,
        Integer srcPort,
        Integer dstPort,
        String protocol,
        int length,
        int score,
        String severity
) {}