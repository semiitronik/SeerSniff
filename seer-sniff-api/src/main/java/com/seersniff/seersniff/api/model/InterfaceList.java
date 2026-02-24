package com.seersniff.seersniff.api.model;

import java.util.List;

public record InterfaceList(
        String sensorId,
        long ts,
        List<InterfaceInfo> interfaces
) {}