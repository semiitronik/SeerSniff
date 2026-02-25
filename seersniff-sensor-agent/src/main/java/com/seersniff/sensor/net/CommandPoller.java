package com.seersniff.sensor.net;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seersniff.sensor.capture.CaptureEngine;
import com.seersniff.sensor.net.dto.SensorCommand;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * Fixed version with:
 * - Proper connection cleanup (disconnect in finally block)
 * - Proper stream handling (try-with-resources)
 * - HTTP timeout settings
 * - Better exception logging instead of swallowing
 * - Consecutive error tracking to avoid infinite retry loops
 */
public class CommandPoller implements Runnable {

    private final String baseUrl;
    private final String sensorId;
    private final CaptureEngine engine;
    private final ObjectMapper om = new ObjectMapper();

    private static final int CONNECT_TIMEOUT_MS = 5000;
    private static final int READ_TIMEOUT_MS = 5000;
    private static final int MAX_CONSECUTIVE_ERRORS = 10;

    public CommandPoller(String baseUrl, String sensorId, CaptureEngine engine) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length()-1) : baseUrl;
        this.sensorId = sensorId;
        this.engine = engine;
    }

    @Override
    public void run() {
        int consecutiveErrors = 0;

        while (true) {
            try {
                SensorCommand cmd = fetchNext();
                if (cmd != null) {
                    handle(cmd);
                    consecutiveErrors = 0;  // Reset on successful command
                }
                Thread.sleep(800);

            } catch (InterruptedException ie) {
                System.out.println("[CommandPoller] Interrupted, shutting down");
                return;

            } catch (Exception e) {
                consecutiveErrors++;
                System.err.println("[CommandPoller] Error (attempt " + consecutiveErrors + "): " + e.getClass().getSimpleName() + ": " + e.getMessage());

                // Fail-safe: don't retry forever
                if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                    System.err.println("[CommandPoller] Too many consecutive errors (" + consecutiveErrors + "), shutting down");
                    return;
                }

                // Back off with exponential delay
                try {
                    Thread.sleep(1500 * Math.min(consecutiveErrors, 4));  // Max 6 second backoff
                } catch (InterruptedException ie) {
                    System.out.println("[CommandPoller] Interrupted during backoff");
                    return;
                }
            }
        }
    }

    /**
     * Fetch next command from server.
     * ✅ FIXED: Proper connection cleanup with try-finally
     * ✅ FIXED: Timeout settings
     * ✅ FIXED: Proper stream handling
     */
    private SensorCommand fetchNext() throws Exception {
        URL url = new URL(baseUrl + "/command/next?sensorId=" + sensorId);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();

        try {
            // Set timeouts to prevent hanging
            con.setConnectTimeout(CONNECT_TIMEOUT_MS);
            con.setReadTimeout(READ_TIMEOUT_MS);
            con.setRequestMethod("GET");

            int code = con.getResponseCode();
            if (code != 200) {
                return null;
            }

            // Use try-with-resources for proper stream closure
            byte[] bytes;
            try (InputStream is = con.getInputStream()) {
                bytes = is.readAllBytes();
            }

            String body = new String(bytes, StandardCharsets.UTF_8).trim();
            if (body.isEmpty() || body.equals("null")) {
                return null;
            }

            return om.readValue(body, SensorCommand.class);

        } finally {
            // ✅ ALWAYS disconnect, even if an exception occurs
            con.disconnect();
        }
    }

    /**
     * Handle command from server.
     * ✅ IMPROVED: Added error logging in switch cases
     */
    private void handle(SensorCommand cmd) throws Exception {
        if (cmd == null || cmd.type() == null) {
            System.err.println("[CommandPoller] Received null or invalid command");
            return;
        }

        try {
            switch (cmd.type()) {

                case "LIST_INTERFACES" -> {
                    try {
                        System.out.println(engine.listInterfaces());
                    } catch (Exception e) {
                        System.err.println("[CommandPoller] Error listing interfaces: " + e.getMessage());
                    }
                }

                case "SELECT_INTERFACE" -> {
                    if (cmd.ifaceIndex() != null) {
                        try {
                            engine.selectInterfaceByIndex(cmd.ifaceIndex());
                        } catch (Exception e) {
                            System.err.println("[CommandPoller] Error selecting interface " + cmd.ifaceIndex() + ": " + e.getMessage());
                        }
                    }
                }

                case "START" -> {
                    try {
                        if (cmd.ifaceIndex() != null) {
                            engine.selectInterfaceByIndex(cmd.ifaceIndex());
                        }
                        engine.start();
                    } catch (Exception e) {
                        System.err.println("[CommandPoller] Error starting capture: " + e.getMessage());
                    }
                }

                case "STOP" -> {
                    try {
                        engine.stop();
                    } catch (Exception e) {
                        System.err.println("[CommandPoller] Error stopping capture: " + e.getMessage());
                    }
                }

                case "TEST_ALERT" -> {
                    try {
                        engine.sendAlert(
                                "HIGH",
                                95,
                                "Manual test alert from WebUI",
                                java.util.List.of(
                                        "Simulated TCP port scan burst",
                                        "High-risk service targeted (3389)"
                                ),
                                java.util.Map.of(
                                        "TcpPortScanBurstRule", 40,
                                        "HighRiskPortRule", 30,
                                        "CorrelationBonus", 15
                                )
                        );
                    } catch (Exception e) {
                        System.err.println("[CommandPoller] Error sending test alert: " + e.getMessage());
                    }
                }

                case "FETCH_PACKET_DETAILS" -> {
                    if (cmd.packetId() != null) {
                        try {
                            engine.sendPacketDetails(cmd.packetId());
                        } catch (Exception e) {
                            System.err.println("[CommandPoller] Error fetching packet details for " + cmd.packetId() + ": " + e.getMessage());
                        }
                    }
                }

                default -> {
                    System.err.println("[CommandPoller] Unknown command type: " + cmd.type());
                }
            }
        } catch (Exception e) {
            System.err.println("[CommandPoller] Unexpected error handling command: " + e.getMessage());
            e.printStackTrace();
        }
    }
}