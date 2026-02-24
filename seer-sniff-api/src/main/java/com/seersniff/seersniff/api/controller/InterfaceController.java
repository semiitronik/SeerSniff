package com.seersniff.seersniff.api.controller;

import com.seersniff.seersniff.api.model.InterfaceList;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/ingest")
public class InterfaceController {

    private final SimpMessagingTemplate messaging;
    private final Map<String, InterfaceList> latestBySensor = new ConcurrentHashMap<>();

    public InterfaceController(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @PostMapping("/interfaces")
    public Map<String, Object> ingest(@RequestBody InterfaceList list) {
        latestBySensor.put(list.sensorId(), list);
        messaging.convertAndSend("/topic/interfaces/" + list.sensorId(), list);
        return Map.of("ok", true);
    }

    @GetMapping("/interfaces/{sensorId}/latest")
    public InterfaceList latest(@PathVariable String sensorId) {
        return latestBySensor.get(sensorId);
    }
}