package com.seersniff.seersniff.api.controller;

import com.seersniff.seersniff.api.model.PacketDetails;
import com.seersniff.seersniff.api.model.PacketSummary;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/ingest")
public class PacketController {

    private final SimpMessagingTemplate messaging;

    // per-sensor rolling buffers
    private final Map<String, Deque<PacketSummary>> packetLists = new ConcurrentHashMap<>();
    private final Map<String, Map<Long, PacketDetails>> packetDetails = new ConcurrentHashMap<>();

    // tune this (don’t keep infinite packets in RAM)
    private static final int MAX_PACKETS_PER_SENSOR = 2000;

    public PacketController(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @PostMapping("/packet")
    public Map<String,Object> ingestPacket(@RequestBody PacketDetails details) {
        // broadcast summary for list view
        PacketSummary summary = new PacketSummary(
                details.sensorId(),
                details.ts(),
                details.packetId(),
                null, null, null, null,
                null,
                details.rawText() != null ? details.rawText().length() : 0,
                details.score(),
                details.severity()

        );

        // store summary + details
        packetLists.computeIfAbsent(details.sensorId(), k -> new ArrayDeque<>());
        packetDetails.computeIfAbsent(details.sensorId(), k -> new ConcurrentHashMap<>());

        Deque<PacketSummary> q = packetLists.get(details.sensorId());
        q.addLast(summary);
        packetDetails.get(details.sensorId()).put(details.packetId(), details);

        while (q.size() > MAX_PACKETS_PER_SENSOR) {
            PacketSummary removed = q.removeFirst();
            packetDetails.get(details.sensorId()).remove(removed.packetId());
        }

        // WS broadcasts
        messaging.convertAndSend("/topic/packets", summary);
        // optional: also broadcast details (usually not needed; REST fetch is cleaner)
        // messaging.convertAndSend("/topic/packetDetails", details);

        return Map.of("ok", true, "packetId", details.packetId());
    }

    // UI: load last N packets on page load
    @GetMapping("/packets/{sensorId}")
    public List<PacketSummary> getPackets(@PathVariable String sensorId,
                                          @RequestParam(defaultValue = "200") int limit) {
        Deque<PacketSummary> q = packetLists.getOrDefault(sensorId, new ArrayDeque<>());
        int n = Math.min(limit, q.size());

        // return last n items
        ArrayList<PacketSummary> out = new ArrayList<>(n);
        Iterator<PacketSummary> it = q.descendingIterator();
        while (it.hasNext() && out.size() < n) out.add(it.next());
        Collections.reverse(out);
        return out;
    }

    // UI: click → fetch details
    @GetMapping("/packet/{sensorId}/{packetId}")
    public PacketDetails getPacket(@PathVariable String sensorId, @PathVariable long packetId) {
        Map<Long, PacketDetails> map = packetDetails.get(sensorId);
        if (map == null) return null;
        return map.get(packetId);
    }
}