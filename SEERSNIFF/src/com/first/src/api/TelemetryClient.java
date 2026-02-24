package com.first.src.api; // change package to match your sniffer project

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

public class TelemetryClient {

    private final HttpClient http = HttpClient.newHttpClient();
    private final URI endpoint;
    private final String sensorId;

    public TelemetryClient(String baseUrl, String sensorId) {
        // baseUrl example: "http://localhost:8080"
        this.endpoint = URI.create(baseUrl + "/ingest/telemetry");
        this.sensorId = sensorId;
    }

    public void sendTelemetry(
            boolean capturing,
            long packetsCaptured,
            long packetsDropped,
            double packetsPerSec,
            int activeFlows,
            int queueDepth
    ) {
        long ts = Instant.now().toEpochMilli();

        String json = "{"
                + "\"sensorId\":\"" + escape(sensorId) + "\","
                + "\"ts\":" + ts + ","
                + "\"capturing\":" + capturing + ","
                + "\"packetsCaptured\":" + packetsCaptured + ","
                + "\"packetsDropped\":" + packetsDropped + ","
                + "\"packetsPerSec\":" + packetsPerSec + ","
                + "\"activeFlows\":" + activeFlows + ","
                + "\"queueDepth\":" + queueDepth
                + "}";

        HttpRequest req = HttpRequest.newBuilder(endpoint)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8))
                .build();

        // fire-and-forget
        http.sendAsync(req, HttpResponse.BodyHandlers.discarding())
                .exceptionally(ex -> {
                    System.err.println("[TelemetryClient] Failed to send telemetry: " + ex.getMessage());
                    return null;
                });
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}