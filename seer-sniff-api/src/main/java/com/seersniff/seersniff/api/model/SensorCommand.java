package com.seersniff.seersniff.api.model;

public record SensorCommand(
        String sensorId,
        String type,       // LIST_INTERFACES, SELECT_INTERFACE, START, STOP
        Integer ifaceIndex,
        Long packetId
) {}