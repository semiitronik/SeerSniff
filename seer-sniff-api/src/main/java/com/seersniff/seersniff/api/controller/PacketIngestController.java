package com.seersniff.seersniff.api.controller;

import com.seersniff.seersniff.api.model.PacketDetails;
import com.seersniff.seersniff.api.model.PacketSummary;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/ingest")
public class PacketIngestController {

    private final SimpMessagingTemplate messaging;

    // store details after sensor posts them (key = sensorId + ":" + packetId)
    private final ConcurrentHashMap<String, PacketDetails> detailsStore = new ConcurrentHashMap<>();

    public PacketIngestController(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @PostMapping("/packet/summary")
    public Map<String,Object> ingestSummary(@RequestBody PacketSummary s) {
        messaging.convertAndSend("/topic/packets", s);
        return Map.of("ok", true);
    }

    @PostMapping("/packet/details")
    public Map<String,Object> ingestDetails(@RequestBody PacketDetails d) {
        detailsStore.put(key(d.sensorId(), d.packetId()), d);
        messaging.convertAndSend("/topic/packetDetails", d);
        return Map.of("ok", true);
    }

    // Optional REST fallback if you want:
    @GetMapping("/packet/details/{sensorId}/{packetId}")
    public PacketDetails getDetails(@PathVariable String sensorId, @PathVariable long packetId) {
        return detailsStore.get(key(sensorId, packetId));
    }

    private static String key(String sensorId, long packetId) {
        return sensorId + ":" + packetId;
    }
}