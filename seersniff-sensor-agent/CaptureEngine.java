package com.seersniff.sensor.capture;

import com.seersniff.sensor.analysis.PacketAnalyzer;
import com.seersniff.sensor.analysis.PacketMeta;
import com.seersniff.sensor.analysis.Severity;
import com.seersniff.sensor.analysis.SuspicionResult;
import com.seersniff.sensor.analysis.SuspicionRule;
import com.seersniff.sensor.analysis.rules.HighRiskPortRule;
import com.seersniff.sensor.analysis.rules.IcmpBurstRule;
import com.seersniff.sensor.analysis.rules.TcpPortScanBurstRule;
import com.seersniff.sensor.analysis.rules.TcpRstBurstRule;
import com.seersniff.sensor.analysis.rules.TcpScanFlagRule;
import com.seersniff.sensor.analysis.rules.UdpPortFanoutRule;
import com.seersniff.sensor.net.ApiClient;
import com.seersniff.sensor.net.dto.AlertEvent;
import com.seersniff.sensor.net.dto.PacketDetails;
import com.seersniff.sensor.net.dto.PacketSummary;
import com.seersniff.sensor.net.dto.Telemetry;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class CaptureEngine {

    private final String sensorId;
    private final ApiClient api;

    private volatile PcapNetworkInterface device;
    private volatile PcapHandle handle;
    private volatile Thread captureThread;

    private final AtomicBoolean capturing = new AtomicBoolean(false);

    private final AtomicLong packetsCaptured = new AtomicLong(0);
    private final AtomicLong packetsDropped = new AtomicLong(0);

    // packets/sec calculation
    private volatile long lastPpsTimeMs = System.currentTimeMillis();
    private volatile long lastPpsCount = 0;

    // Packet IDs for web list selection + details fetch
    private final AtomicLong packetIdSeq = new AtomicLong(0);

    // ---- Option B: cache details locally, only send on FETCH_PACKET_DETAILS ----
    private static final int MAX_DETAIL_CACHE = 1000;
    private final Map<Long, PacketDetails> detailCache = new ConcurrentHashMap<>();
    private final Deque<Long> detailOrder = new ArrayDeque<>();

    // Analyzer (make sure these rule classes exist in your sensor project)
    private final PacketAnalyzer analyzer = new PacketAnalyzer(List.of(
            new TcpScanFlagRule(),
            new TcpPortScanBurstRule(),
            new TcpRstBurstRule(),
            new UdpPortFanoutRule(),
            new HighRiskPortRule(),
            new IcmpBurstRule()
    ));

    public CaptureEngine(String sensorId, ApiClient api) {
        this.sensorId = sensorId;
        this.api = api;
    }

    // ====== Interfaces (for WebUI) ======

    /** Returns all capture interfaces as display strings like: "[0] Intel(R) ...". */
    public List<String> listInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> ifs = Pcaps.findAllDevs();
        List<String> out = new ArrayList<>();
        if (ifs == null) return out;

        for (int i = 0; i < ifs.size(); i++) {
            PcapNetworkInterface nif = ifs.get(i);
            String label = (nif.getDescription() != null && !nif.getDescription().isBlank())
                    ? nif.getDescription()
                    : nif.getName();
            out.add("[" + i + "] " + label);
        }
        return out;
    }

    /** Select by index (WebUI will send the index). */
    public void selectInterfaceByIndex(int ifaceIndex) throws PcapNativeException {
        if (capturing.get()) throw new IllegalStateException("Stop capture before switching interfaces.");

        List<PcapNetworkInterface> ifs = Pcaps.findAllDevs();
        if (ifs == null || ifs.isEmpty()) throw new IllegalStateException("No interfaces found.");
        if (ifaceIndex < 0 || ifaceIndex >= ifs.size()) throw new IllegalArgumentException("Invalid ifaceIndex: " + ifaceIndex);

        selectInterface(ifs.get(ifaceIndex));
    }

    public void selectInterface(PcapNetworkInterface nif) {
        if (capturing.get()) throw new IllegalStateException("Stop capture before switching interfaces.");
        this.device = nif;
        System.out.println("[CaptureEngine] Selected: " + (nif == null ? "(none)" : nif.getName()));
    }

    public boolean isCapturing() {
        return capturing.get();
    }

    // ====== Capture control (for WebUI) ======

    /** Start capture on the currently selected interface. */
    public void start() {
        if (capturing.get()) return;
        if (device == null) throw new IllegalStateException("No interface selected.");

        capturing.set(true);

        captureThread = new Thread(() -> {
            Thread telemetryThread = null;

            try {
                packetsCaptured.set(0);
                packetsDropped.set(0);

                int snaplen = 65536;
                int timeoutMs = 150;

                handle = device.openLive(snaplen, PromiscuousMode.PROMISCUOUS, timeoutMs);

                // telemetry loop thread
                telemetryThread = new Thread(this::telemetryLoop, "telemetry-loop");
                telemetryThread.setDaemon(true);
                telemetryThread.start();

                while (capturing.get() && handle != null && handle.isOpen()) {

                    Packet packet;
                    try {
                        packet = handle.getNextPacket(); // null on timeout
                    } catch (NotOpenException e) {
                        break;
                    }

                    if (packet == null) continue;

                    packetsCaptured.incrementAndGet();

                    long packetId = packetIdSeq.incrementAndGet();
                    long ts = System.currentTimeMillis();

                    // Analyze
                    SuspicionResult result = analyzer.analyze(packet);

                    // Cache FULL details locally (Option B)
                    PacketDetails details = new PacketDetails(
                            sensorId,
                            ts,
                            packetId,
                            result.getScore(),
                            result.getSeverity().name(),
                            result.getReasons(),
                            result.getRuleScores(),
                            packet.toString()
                    );

                    cacheDetails(packetId, details);

                    // Send only SUMMARY to backend for list display
                    PacketMeta m = PacketMeta.from(packet);
                    String protocol = m.isTcp ? "TCP" : (m.isUdp ? "UDP" : (m.isIcmp ? "ICMP" : "OTHER"));

                    PacketSummary summary = new PacketSummary(
                            sensorId,
                            ts,
                            packetId,
                            m.srcIp,
                            m.dstIp,
                            m.srcPort,
                            m.dstPort,
                            protocol,
                            m.length,
                            result.getScore(),
                            result.getSeverity().name()
                    );

                    api.postPacketSummary(summary);

                    // Send alerts for MEDIUM/HIGH
                    if (result.getSeverity() == Severity.HIGH || result.getSeverity() == Severity.MEDIUM) {
                        sendAlert(
                                result.getSeverity().name(),
                                result.getScore(),
                                "Suspicious network activity",
                                result.getReasons(),
                                result.getRuleScores()
                        );
                    }
                }

            } catch (Exception e) {
                System.err.println("[CaptureEngine] Capture error: " + e.getMessage());
            } finally {
                capturing.set(false);
                safeClose();

                if (telemetryThread != null) telemetryThread.interrupt();
                System.out.println("[CaptureEngine] Stopped.");
            }
        }, "capture-thread");

        captureThread.start();
        System.out.println("[CaptureEngine] Started.");
    }

    public void stop() {
        capturing.set(false);
        safeClose();
        if (captureThread != null) captureThread.interrupt();
    }

    private void safeClose() {
        try {
            if (handle != null && handle.isOpen()) handle.close();
        } catch (Exception ignored) {
        }
    }

    private void cacheDetails(long packetId, PacketDetails details) {
        detailCache.put(packetId, details);
        detailOrder.addLast(packetId);

        while (detailOrder.size() > MAX_DETAIL_CACHE) {
            Long old = detailOrder.removeFirst();
            if (old != null) detailCache.remove(old);
        }
    }

    /**
     * Called by CommandPoller when UI requests FETCH_PACKET_DETAILS (Option B).
     * This posts ONE packet’s details to backend, which then broadcasts to WebUI via WS.
     */
    public void sendPacketDetails(Long packetId) {
        if (packetId == null) return;

        PacketDetails details = detailCache.get(packetId);
        if (details != null) {
            api.postPacketDetails(details);
        } else {
            System.out.println("[CaptureEngine] details not found for packetId=" + packetId);
        }
    }

    private void telemetryLoop() {
        while (capturing.get()) {
            try {
                long now = System.currentTimeMillis();
                long count = packetsCaptured.get();
                double pps = calcPps(now, count);

                Telemetry t = new Telemetry(
                        sensorId,
                        now,
                        true,
                        packetsCaptured.get(),
                        packetsDropped.get(),
                        pps,
                        0,
                        0
                );

                api.postTelemetry(t);
                Thread.sleep(1000);

            } catch (InterruptedException ie) {
                return;
            } catch (Exception e) {
                System.err.println("[CaptureEngine] telemetryLoop error: " + e.getMessage());
            }
        }

        // final capturing=false telemetry
        try {
            long now = System.currentTimeMillis();
            Telemetry t = new Telemetry(
                    sensorId,
                    now,
                    false,
                    packetsCaptured.get(),
                    packetsDropped.get(),
                    0.0,
                    0,
                    0
            );
            api.postTelemetry(t);
        } catch (Exception ignored) {
        }
    }

    private double calcPps(long nowMs, long totalCount) {
        long dt = nowMs - lastPpsTimeMs;
        if (dt <= 0) return 0.0;

        long dCount = totalCount - lastPpsCount;
        double pps = (dCount * 1000.0) / dt;

        // refresh every ~1 second
        if (dt >= 900) {
            lastPpsTimeMs = nowMs;
            lastPpsCount = totalCount;
        }
        return pps;
    }

    public void sendAlert(String severity, int score, String summary, List<String> reasons, Map<String, Integer> ruleScores) {
        AlertEvent alert = new AlertEvent(
                sensorId,
                System.currentTimeMillis(),
                severity,
                score,
                summary,
                reasons,
                ruleScores
        );
        api.postAlert(alert);
    }

    /** Optional: if you want to expose analyzer rules for debug/testing. */
    public List<SuspicionRule> getRules() {
        return analyzer.getRules();
    }
}