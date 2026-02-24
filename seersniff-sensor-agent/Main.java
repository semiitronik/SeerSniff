package com.seersniff.sensor;

import com.seersniff.sensor.capture.CaptureEngine;
import com.seersniff.sensor.net.ApiClient;
import com.seersniff.sensor.net.CommandPoller;

public class Main {

    public static void main(String[] args) {
        String baseUrl = (args.length >= 1) ? args[0] : "http://localhost:8080";
        String sensorId = (args.length >= 2) ? args[1] : "desktop-sniffer-1";

        ApiClient api = new ApiClient(baseUrl);
        CaptureEngine engine = new CaptureEngine(sensorId, api);

        Thread poller = new Thread(new CommandPoller(baseUrl, sensorId, engine), "command-poller");
        poller.setDaemon(true);
        poller.start();

        System.out.println("Sensor-agent running. sensorId=" + sensorId + " backend=" + baseUrl);

        // keep alive
        while (true) {
            try { Thread.sleep(10_000); } catch (InterruptedException e) { return; }
        }
    }
}