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

/**
 * Fixed version with:
 * - Proper connection cleanup with try-finally blocks
 * - HTTP timeout settings
 * - Better exception handling and logging
 * - Proper resource management
 */
public class ApiClient {

    private final String baseUrl;
    private final ObjectMapper om = new ObjectMapper();

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;

    public ApiClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/")
                ? baseUrl.substring(0, baseUrl.length() - 1)
                : baseUrl;
    }

    // ===================== TELEMETRY =====================

    /**
     * Post telemetry data to backend.
     * ✅ FIXED: Exception handling with logging
     */
    public void postTelemetry(Telemetry telemetry) {
        if (telemetry == null) {
            System.err.println("[ApiClient] Cannot post null telemetry");
            return;
        }

        try {
            String json = om.writeValueAsString(telemetry);
            postJson("/ingest/telemetry", json);
        } catch (Exception e) {
            System.err.println("[ApiClient] postTelemetry failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ===================== ALERTS =====================

    /**
     * Post security alert to backend.
     * ✅ FIXED: Exception handling with logging
     */
    public void postAlert(AlertEvent alert) {
        if (alert == null) {
            System.err.println("[ApiClient] Cannot post null alert");
            return;
        }

        try {
            String json = om.writeValueAsString(alert);
            postJson("/ingest/alert", json);
        } catch (Exception e) {
            System.err.println("[ApiClient] postAlert failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ===================== PACKET STREAM =====================

    /**
     * Post packet summary to backend for WebUI list display.
     * ✅ FIXED: Exception handling with logging
     */
    public void postPacketSummary(PacketSummary summary) {
        if (summary == null) {
            System.err.println("[ApiClient] Cannot post null packet summary");
            return;
        }

        try {
            String json = om.writeValueAsString(summary);
            postJson("/ingest/packet/summary", json);
        } catch (Exception e) {
            System.err.println("[ApiClient] postPacketSummary failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    /**
     * Post full packet details when WebUI requests them.
     * ✅ FIXED: Exception handling with logging
     */
    public void postPacketDetails(PacketDetails details) {
        if (details == null) {
            System.err.println("[ApiClient] Cannot post null packet details");
            return;
        }

        try {
            String json = om.writeValueAsString(details);
            postJson("/ingest/packet/details", json);
        } catch (Exception e) {
            System.err.println("[ApiClient] postPacketDetails failed: " + e.getClass().getSimpleName() + ": " + e.getMessage());
        }
    }

    // ===================== INTERNAL =====================

    /**
     * Post JSON to backend endpoint.
     * ✅ FIXED: Proper try-finally for connection cleanup
     * ✅ FIXED: Timeout settings
     * ✅ FIXED: Better error reporting
     */
    private void postJson(String path, String json) throws Exception {
        if (path == null || json == null) {
            throw new IllegalArgumentException("path and json cannot be null");
        }

        URL url = new URL(baseUrl + path);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        try {
            // Set timeouts to prevent hanging
            con.setConnectTimeout(CONNECT_TIMEOUT_MS);
            con.setReadTimeout(READ_TIMEOUT_MS);

            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setDoOutput(true);

            // Write request body
            try (OutputStream os = con.getOutputStream()) {
                os.write(json.getBytes(StandardCharsets.UTF_8));
                os.flush();  // Explicit flush for clarity
            }

            // Check response code
            int code = con.getResponseCode();
            if (code < 200 || code >= 300) {
                // Read error response if available
                String errorMsg = "HTTP " + code + " for " + path;
                try {
                    byte[] errBytes = con.getErrorStream().readAllBytes();
                    if (errBytes.length > 0) {
                        String errBody = new String(errBytes, StandardCharsets.UTF_8);
                        errorMsg += " - Response: " + errBody;
                    }
                } catch (Exception ignore) {
                    // Error stream read failed, use original message
                }

                throw new RuntimeException(errorMsg);
            }

        } finally {
            // ✅ ALWAYS disconnect, even if an exception occurs
            try {
                con.disconnect();
            } catch (Exception ignore) {
                // Ignore disconnect errors
            }
        }
    }
}