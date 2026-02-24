package com.seersniff.seersniff.api.controller;

import com.seersniff.seersniff.api.model.AlertEvent;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@RestController
@RequestMapping("/ingest")
public class AlertController {

    private final SimpMessagingTemplate messaging;

    // Optional: keeps last alert so UI can fetch it on load
    private final AtomicReference<AlertEvent> latest = new AtomicReference<>();

    public AlertController(SimpMessagingTemplate messaging) {
        this.messaging = messaging;
    }

    @PostMapping("/alert")
    public Map<String, Object> ingestAlert(@RequestBody AlertEvent alert) {
        latest.set(alert);

        // Broadcast to UI subscribers
        messaging.convertAndSend("/topic/alerts", alert);

        return Map.of("ok", true, "received", alert);
    }

    @GetMapping("/alert/latest")
    public AlertEvent getLatest() {
        return latest.get();
    }
}