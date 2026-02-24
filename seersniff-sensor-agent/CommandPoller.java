package com.seersniff.sensor.net;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.seersniff.sensor.capture.CaptureEngine;
import com.seersniff.sensor.net.dto.SensorCommand;

import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

public class CommandPoller implements Runnable {

    private final String baseUrl;
    private final String sensorId;
    private final CaptureEngine engine;
    private final ObjectMapper om = new ObjectMapper();

    public CommandPoller(String baseUrl, String sensorId, CaptureEngine engine) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length()-1) : baseUrl;
        this.sensorId = sensorId;
        this.engine = engine;
    }

    @Override
    public void run() {
        while (true) {
            try {
                SensorCommand cmd = fetchNext();
                if (cmd != null) handle(cmd);
                Thread.sleep(800);
            } catch (InterruptedException ie) {
                return;
            } catch (Exception ignored) {
                try { Thread.sleep(1500); } catch (InterruptedException e) { return; }
            }
        }
    }

    private SensorCommand fetchNext() throws Exception {
        URL url = new URL(baseUrl + "/command/next?sensorId=" + sensorId);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        con.setRequestMethod("GET");

        int code = con.getResponseCode();
        if (code != 200) return null;

        byte[] bytes = con.getInputStream().readAllBytes();
        String body = new String(bytes, StandardCharsets.UTF_8).trim();
        if (body.isEmpty() || body.equals("null")) return null;

        return om.readValue(body, SensorCommand.class);
    }

    private void handle(SensorCommand cmd) throws Exception {
        switch (cmd.type()) {

            case "LIST_INTERFACES" -> {
                System.out.println(engine.listInterfaces());
            }

            case "SELECT_INTERFACE" -> {
                if (cmd.ifaceIndex() != null)
                    engine.selectInterfaceByIndex(cmd.ifaceIndex());
            }

            case "START" -> {
                if (cmd.ifaceIndex() != null)
                    engine.selectInterfaceByIndex(cmd.ifaceIndex());
                engine.start();
            }

            case "STOP" -> engine.stop();

            case "TEST_ALERT" -> {
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
            }
            case "FETCH_PACKET_DETAILS" -> {
                if (cmd.packetId() != null) {
                    engine.sendPacketDetails(cmd.packetId());
                }
            }}
    }}