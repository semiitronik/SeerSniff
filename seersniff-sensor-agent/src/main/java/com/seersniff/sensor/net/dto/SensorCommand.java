package com.seersniff.sensor.net.dto;

public record SensorCommand(
        String sensorId,
        String type,
        Integer ifaceIndex,
        Long packetId
) {}