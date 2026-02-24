package com.seersniff.seersniff.api.controller;

import com.seersniff.seersniff.api.model.Telemetry;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

@RestController
@RequestMapping("/ingest")
public class TelemetryController {

	private final SimpMessagingTemplate messaging;
	private final AtomicReference<Telemetry> latest = new AtomicReference<>();

	public TelemetryController(SimpMessagingTemplate messaging) {
		this.messaging = messaging;
	}

	// 🔥 THIS IS WHAT YOU ARE MISSING
	@PostMapping("/telemetry")
	public Map<String, Object> ingestTelemetry(@RequestBody Telemetry telemetry) {
		latest.set(telemetry);

		// Broadcast to WebSocket subscribers
		messaging.convertAndSend("/topic/telemetry", telemetry);

		return Map.of("ok", true);
	}

	@GetMapping("/telemetry/latest")
	public Telemetry getLatest() {
		return latest.get();
	}
}