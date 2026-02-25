package com.seersniff.seersniff.api.controller;

import com.seersniff.seersniff.api.model.SensorCommand;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

@RestController
@RequestMapping("/command")
public class CommandController {

    private final SimpMessagingTemplate messaging;
    private final Map<String, Queue<SensorCommand>> queues = new ConcurrentHashMap<>();

    public CommandController(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @PostMapping("/send")
    public Map<String, Object> send(@RequestBody SensorCommand cmd) {
        if (cmd == null || cmd.sensorId() == null || cmd.type() == null) {
            return Map.of("ok", false, "error", "invalid command");
        }

        queues.computeIfAbsent(cmd.sensorId(), k -> new ConcurrentLinkedQueue<>()).add(cmd);

        // broadcast to WebUI so admin sees the command
        try {
            messaging.convertAndSend("/topic/command/" + cmd.sensorId(), cmd);
        } catch (Exception e) {
            System.err.println("[CommandController] broadcast failed: " + e.getMessage());
        }

        return Map.of("ok", true);
    }

    @GetMapping("/next")
    public SensorCommand next(@RequestParam String sensorId) {
        Queue<SensorCommand> q = queues.get(sensorId);
        if (q == null) return null;
        return q.poll();
    }
}