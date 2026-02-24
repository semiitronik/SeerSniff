package com.first.src.api;

import com.first.src.analysis.SuspicionResult;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

public class AlertClient {

    private final String baseUrl;   // e.g. "http://localhost:8080"
    private final String sensorId;  // e.g. "desktop-sniffer-1"

    public AlertClient(String baseUrl, String sensorId) {
        this.baseUrl = baseUrl;
        this.sensorId = sensorId;
    }

    public void sendAlert(SuspicionResult r) {
        try {
            long ts = System.currentTimeMillis();

            String reasonsJson = r.getReasons() == null ? "[]" :
                    "[" + r.getReasons().stream()
                            .map(AlertClient::json)
                            .collect(Collectors.joining(",")) + "]";

            String ruleScoresJson = (r.getRuleScores() == null || r.getRuleScores().isEmpty())
                    ? "{}"
                    : "{" + r.getRuleScores().entrySet().stream()
                    .map(e -> json(e.getKey()) + ":" + (e.getValue() == null ? 0 : e.getValue()))
                    .collect(Collectors.joining(",")) + "}";

            String summary = "Suspicious packet detected";

            String body = "{"
                    + "\"sensorId\":" + json(sensorId) + ","
                    + "\"ts\":" + ts + ","
                    + "\"severity\":" + json(r.getSeverity().name()) + ","
                    + "\"score\":" + r.getScore() + ","
                    + "\"summary\":" + json(summary) + ","
                    + "\"reasons\":" + reasonsJson + ","
                    + "\"ruleScores\":" + ruleScoresJson
                    + "}";

            URL url = new URL(baseUrl + "/ingest/alert");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/json");
            con.setDoOutput(true);

            try (OutputStream os = con.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }

            // force request to complete
            con.getResponseCode();
            con.disconnect();
        } catch (Exception ignored) {
            // keep sniffer stable; do not crash capture thread
        }
    }

    private static String json(String s) {
        if (s == null) return "null";
        return "\"" + s
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t") + "\"";
    }
}