package com.first.src.api; // change package to match your sniffer project

public class TelemetryLoop {

    private final TelemetryClient client;

    private volatile boolean capturing;
    private volatile long packetsCaptured;
    private volatile long packetsDropped;

    private long lastCaptured;
    private long lastTimeMs;

    // Optional fields
    private volatile int activeFlows;
    private volatile int queueDepth;

    public TelemetryLoop(TelemetryClient client) {
        this.client = client;
        this.lastTimeMs = System.currentTimeMillis();
    }

    public void setCapturing(boolean capturing) {
        this.capturing = capturing;
    }

    public void onPacketCaptured() {
        packetsCaptured++;
    }

    public void onPacketDropped() {
        packetsDropped++;
    }

    public void setActiveFlows(int activeFlows) {
        this.activeFlows = activeFlows;
    }

    public void setQueueDepth(int queueDepth) {
        this.queueDepth = queueDepth;
    }

    /** Call this once per second (or on a scheduled timer). */
    public void tick() {
        long now = System.currentTimeMillis();
        long dt = now - lastTimeMs;
        if (dt <= 0) dt = 1;

        long capturedDelta = packetsCaptured - lastCaptured;
        double perSec = (capturedDelta * 1000.0) / dt;

        client.sendTelemetry(
                capturing,
                packetsCaptured,
                packetsDropped,
                perSec,
                activeFlows,
                queueDepth
        );

        lastCaptured = packetsCaptured;
        lastTimeMs = now;
    }
}