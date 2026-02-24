package com.seersniff.sensor.net;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seersniff.sensor.net.dto.AlertEvent;
import com.seersniff.sensor.net.dto.PacketDetails;
import com.seersniff.sensor.net.dto.PacketSummary;
import com.seersniff.sensor.net.dto.Telemetry;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class ApiClient {

    private final String baseUrl;
    private final ObjectMapper om = new ObjectMapper();

    public ApiClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1)
                : baseUrl;
    }

    // ===================== TELEMETRY =====================

    public void postTelemetry(Telemetry telemetry) {
        try {
            postJson("/ingest/telemetry", om.writeValueAsString(telemetry));
        } catch (Exception e) {
            System.err.println("[ApiClient] postTelemetry failed: " + e.getMessage());
        }
    }

    // ===================== ALERTS =====================

    public void postAlert(AlertEvent alert) {
        try {
            postJson("/ingest/alert", om.writeValueAsString(alert));
        } catch (Exception e) {
            System.err.println("[ApiClient] postAlert failed: " + e.getMessage());
        }
    }

    // ===================== PACKET STREAM (Option B) =====================

    public void postPacketSummary(PacketSummary summary) {
        try {
            postJson("/ingest/packet/summary", om.writeValueAsString(summary));
        } catch (Exception e) {
            System.err.println("[ApiClient] postPacketSummary failed: " + e.getMessage());
        }
    }

    public void postPacketDetails(PacketDetails details) {
        try {
            postJson("/ingest/packet/details", om.writeValueAsString(details));
        } catch (Exception e) {
            System.err.println("[ApiClient] postPacketDetails failed: " + e.getMessage());
        }
    }

    // ===================== INTERNAL =====================

    private void postJson(String path, String json) throws Exception {
        URL url = new URL(baseUrl + path);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("POST");
        con.setRequestProperty("Content-Type", "application/json");
        con.setDoOutput(true);

        try (OutputStream os = con.getOutputStream()) {
            os.write(json.getBytes(StandardCharsets.UTF_8));
        }

        int code = con.getResponseCode();
        if (code < 200 || code >= 300) {
            throw new RuntimeException("HTTP " + code + " for " + path);
        }

        con.disconnect();
    }
}