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

/**
 * Fixed version with:
 * - Proper thread synchronization (synchronized start/stop)
 * - Thread.join() with timeout for clean shutdown
 * - Exception handling in packet processing loop
 * - Defensive null checks
 * - Better logging
 */
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

    // ---- cache details locally, only send on FETCH_PACKET_DETAILS ----
    private static final int MAX_DETAIL_CACHE = 1000;
    private final Map<Long, PacketDetails> detailCache = new ConcurrentHashMap<>();
    private final Deque<Long> detailOrder = new ArrayDeque<>();

    // ✅ ADDED: Lock for thread-safe start/stop operations
    private final Object threadLock = new Object();

    // Analyzer
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

    /**
     * Start capture on the currently selected interface.
     * ✅ FIXED: Thread-safe with synchronization and no double-start
     */
    public void start() {
        synchronized (threadLock) {
            if (capturing.get()) {
                System.out.println("[CaptureEngine] Capture already running");
                return;
            }
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

                    System.out.println("[CaptureEngine] Capture started on " + device.getName());

                    // ✅ MAIN PACKET LOOP with exception handling
                    while (capturing.get() && handle != null && handle.isOpen()) {

                        Packet packet;
                        try {
                            packet = handle.getNextPacket(); // null on timeout
                        } catch (NotOpenException e) {
                            System.out.println("[CaptureEngine] Handle closed, stopping capture");
                            break;
                        }

                        if (packet == null) continue;

                        // ✅ FIXED: Wrap packet processing in try-catch to prevent thread death
                        try {
                            packetsCaptured.incrementAndGet();

                            long packetId = packetIdSeq.incrementAndGet();
                            long ts = System.currentTimeMillis();
                            byte[] rawBytes = packet.getRawData();
                            String hexDump = (rawBytes == null) ? "" : bytesToHex(rawBytes);
                            String rawTextCombined = hexDump + "\n\n" + packet.toString();
                            PacketDetails details = new PacketDetails(
                                    sensorId,
                                    ts,
                                    packetId,
                                    r.getScore(),
                                    r.getSeverity().name(),
                                    r.getReasons(),
                                    r.getRuleScores(),
                                    rawTextCombined
                            );

                            cacheDetails(packetId, details);

                            // ✅ Defensive: Analyze packet
                            SuspicionResult result = analyzer.analyze(packet);

                            if (result == null) {
                                System.err.println("[CaptureEngine] Analyzer returned null result");
                                continue;
                            }

                            // ✅ Cache FULL details locally
                            try {
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
                            } catch (Exception e) {
                                System.err.println("[CaptureEngine] Error caching packet details: " + e.getMessage());
                            }

                            // ✅ Extract packet metadata
                            PacketMeta m = PacketMeta.from(packet);
                            String protocol = m.isTcp ? "TCP" : (m.isUdp ? "UDP" : (m.isIcmp ? "ICMP" : "OTHER"));

                            // ✅ Send SUMMARY to backend for list display
                            try {
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
                            } catch (Exception e) {
                                System.err.println("[CaptureEngine] Error posting packet summary: " + e.getMessage());
                            }

                            // ✅ Send alerts for MEDIUM/HIGH severity
                            if (result.getSeverity() == Severity.HIGH || result.getSeverity() == Severity.MEDIUM) {
                                try {
                                    sendAlert(
                                            result.getSeverity().name(),
                                            result.getScore(),
                                            "Suspicious network activity",
                                            result.getReasons(),
                                            result.getRuleScores()
                                    );
                                } catch (Exception e) {
                                    System.err.println("[CaptureEngine] Error sending alert: " + e.getMessage());
                                }
                            }

                        } catch (Exception e) {
                            System.err.println("[CaptureEngine] Error processing packet: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                            // Continue to next packet instead of crashing thread
                        }
                    }

                } catch (Exception e) {
                    System.err.println("[CaptureEngine] Capture error: " + e.getClass().getSimpleName() + ": " + e.getMessage());
                    e.printStackTrace();
                } finally {
                    capturing.set(false);
                    safeClose();

                    if (telemetryThread != null) {
                        telemetryThread.interrupt();
                    }

                    System.out.println("[CaptureEngine] Stopped.");
                }
            }, "capture-thread");

            captureThread.start();
            System.out.println("[CaptureEngine] Started.");
        }
    }

    /**
     * Stop capture.
     * ✅ FIXED: Thread-safe with synchronization and join()
     */
    public void stop() {
        synchronized (threadLock) {
            capturing.set(false);
            safeClose();

            if (captureThread != null) {
                captureThread.interrupt();

                // ✅ Wait for thread to finish (with timeout)
                try {
                    captureThread.join(5000);  // Wait up to 5 seconds
                    if (captureThread.isAlive()) {
                        System.err.println("[CaptureEngine] Capture thread did not terminate within 5 seconds");
                    }
                } catch (InterruptedException e) {
                    System.err.println("[CaptureEngine] Interrupted waiting for capture thread");
                    Thread.currentThread().interrupt();
                }

                captureThread = null;
            }
        }
    }

    private void safeClose() {
        try {
            if (handle != null && handle.isOpen()) {
                handle.close();
            }
        } catch (Exception e) {
            System.err.println("[CaptureEngine] Error closing handle: " + e.getMessage());
        }
    }

    private void cacheDetails(long packetId, PacketDetails details) {
        detailCache.put(packetId, details);
        detailOrder.addLast(packetId);

        // Evict oldest if cache is full
        while (detailOrder.size() > MAX_DETAIL_CACHE) {
            Long old = detailOrder.removeFirst();
            if (old != null) detailCache.remove(old);
        }
    }
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 3); // include spaces
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            if (i % 16 == 0 && i != 0) sb.append('\n');
            else if (i != 0) sb.append(' ');
            sb.append(HEX_ARRAY[v >>> 4]);
            sb.append(HEX_ARRAY[v & 0x0F]);
        }
        return sb.toString();
    }

    public void sendPacketDetails(long packetId) {
        PacketDetails details = detailCache.get(packetId);
        if (details == null) {
            System.err.println("[CaptureEngine] Packet details not found for ID: " + packetId);
            return;
        }

        try {
            api.postPacketDetails(details);
        } catch (Exception e) {
            System.err.println("[CaptureEngine] Error sending packet details: " + e.getMessage());
        }
    }

    // ====== Telemetry Loop (runs on separate thread) ======

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

                try {
                    api.postTelemetry(t);
                } catch (Exception e) {
                    System.err.println("[CaptureEngine] Error posting telemetry: " + e.getMessage());
                }

                Thread.sleep(1000);

            } catch (InterruptedException ie) {
                System.out.println("[CaptureEngine] Telemetry thread interrupted");
                return;
            } catch (Exception e) {
                System.err.println("[CaptureEngine] Telemetry loop error: " + e.getMessage());
            }
        }

        // Send final telemetry with capturing=false
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
        } catch (Exception e) {
            System.err.println("[CaptureEngine] Error posting final telemetry: " + e.getMessage());
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
        try {
            api.postAlert(alert);
        } catch (Exception e) {
            System.err.println("[CaptureEngine] Error sending alert: " + e.getMessage());
        }
    }
}