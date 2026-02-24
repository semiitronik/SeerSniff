package com.first.src;

import com.formdev.flatlaf.FlatLightLaf;
import com.first.src.analysis.PacketAnalyzer;
import com.first.src.analysis.SuspicionResult;
import com.first.src.analysis.rules.HighRiskPortRule;
import com.first.src.analysis.rules.IcmpBurstRule;
import com.first.src.analysis.rules.TcpScanFlagRule;

import com.first.src.analysis.PacketMeta;
import com.first.src.analysis.Severity;
import com.first.src.analysis.rules.TcpPortScanBurstRule;
import com.first.src.analysis.rules.TcpRstBurstRule;
import com.first.src.analysis.rules.UdpPortFanoutRule;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import javax.swing.*;
import java.awt.*;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;

import com.first.src.api.TelemetryClient;
import com.first.src.api.TelemetryLoop;

public class ViewPackets extends JFrame {

    private PcapNetworkInterface device;
    private final List<Packet> packets = new ArrayList<>();
    private final List<SuspicionResult> results = new ArrayList<>();

    private int selectedIndex = -1;

    private PcapHandle handle = null;
    private volatile boolean capturing = false;
    private Thread captureThread;
    // ---- Telemetry to Spring Boot (web UI) ----
    private final TelemetryClient telemetryClient =
            new TelemetryClient("http://localhost:8080", "desktop-sniffer-1");

    private final TelemetryLoop telemetry =
            new TelemetryLoop(telemetryClient);

    private JLabel interfaceLabel;
    private JLabel selectedPacketLabel;
    private final com.first.src.api.AlertClient alertClient =
            new com.first.src.api.AlertClient("http://localhost:8080", "desktop-sniffer-1");

    // Analyzer used for BOTH live capture and PCAP load and tests
    private final PacketAnalyzer analyzer = new PacketAnalyzer(List.of(
            new TcpScanFlagRule(),
            new TcpPortScanBurstRule(),
            new TcpRstBurstRule(),
            new UdpPortFanoutRule(),
            new HighRiskPortRule(),
            new IcmpBurstRule()
    ));

    public ViewPackets(List<PcapNetworkInterface> interfaces, int i) {
        try {
            UIManager.setLookAndFeel(new FlatLightLaf());
        } catch (Exception ignored) {}

        initComponents();

        if (interfaces == null || interfaces.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "No network interfaces were provided.\n" +
                            "Make sure your interface list is loaded before opening Packet Viewer.",
                    "Capture Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        if (i < 0 || i >= interfaces.size()) {
            JOptionPane.showMessageDialog(this,
                    "Invalid interface selection index: " + i,
                    "Capture Error",
                    JOptionPane.ERROR_MESSAGE);
            return;
        }

        device = interfaces.get(i);
        String desc = device.getDescription();
        if (desc == null || desc.isBlank()) desc = device.getName();
        interfaceLabel.setText(desc);
    }

    private void initComponents() {
        setTitle("Packet Viewer");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setSize(900, 600);
        setLayout(new BorderLayout());

        // Header Panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(240, 240, 240));

        JLabel headerLabel = new JLabel("PACKET VIEWER", SwingConstants.CENTER);
        headerLabel.setFont(new Font("Arial", Font.BOLD, 24));
        headerLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        headerPanel.add(headerLabel, BorderLayout.CENTER);

        interfaceLabel = new JLabel("", SwingConstants.LEFT);
        interfaceLabel.setFont(new Font("Arial", Font.PLAIN, 14));
        interfaceLabel.setBorder(BorderFactory.createEmptyBorder(5, 20, 5, 10));
        headerPanel.add(interfaceLabel, BorderLayout.SOUTH);

        // Main Panel
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        DefaultListModel<String> listModel = new DefaultListModel<>();
        JList<String> packetList = new JList<>(listModel);
        packetList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        packetList.setToolTipText("Select a packet to view details");

        // Row coloring based on tags
        packetList.setCellRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(
                    JList<?> list, Object value, int index,
                    boolean isSelected, boolean cellHasFocus) {

                Component c = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                String text = value.toString();

                if (!isSelected) {
                    if (text.startsWith("[HIGH ALERT]")) {
                        c.setBackground(new Color(255, 150, 150)); // light red
                    } else if (text.startsWith("[MEDIUM ALERT]")) {
                        c.setBackground(new Color(255, 220, 160)); // light orange
                    } else {
                        c.setBackground(Color.WHITE);
                    }
                }

                return c;
            }
        });

        packetList.addListSelectionListener(evt -> {
            if (evt.getValueIsAdjusting()) return;
            selectedIndex = packetList.getSelectedIndex();
            if (selectedIndex >= 0 && selectedIndex < results.size()) {
                SuspicionResult r = results.get(selectedIndex);
                selectedPacketLabel.setText(
                        "Packet " + selectedIndex + " | Severity=" + r.getSeverity() + " | Score=" + r.getScore()
                );
            } else if (selectedIndex >= 0) {
                selectedPacketLabel.setText("Packet " + selectedIndex);
            }
        });

        JScrollPane listScrollPane = new JScrollPane(packetList);
        listScrollPane.setBorder(BorderFactory.createTitledBorder("Captured Packets"));
        mainPanel.add(listScrollPane, BorderLayout.CENTER);

        // Footer Panel
        JPanel footerPanel = new JPanel(new BorderLayout());
        footerPanel.setBorder(BorderFactory.createEmptyBorder(10, 20, 10, 20));

        JPanel footerInfoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        footerInfoPanel.add(new JLabel("Selected Packet: "));
        selectedPacketLabel = new JLabel("");
        selectedPacketLabel.setFont(new Font("Arial", Font.PLAIN, 14));
        footerInfoPanel.add(selectedPacketLabel);
        footerPanel.add(footerInfoPanel, BorderLayout.NORTH);

        // Button Panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 20, 10));

        JButton loadPcapButton = new JButton("Load PCAP");
        loadPcapButton.setToolTipText("Load packets from a PCAP file and analyze them");
        loadPcapButton.addActionListener(evt -> loadPcap(listModel));

        JButton startCaptureButton = new JButton("Start Capturing!");
        startCaptureButton.setToolTipText("Start capturing packets on the selected interface");

        JButton stopCaptureButton = new JButton("Stop Capturing");
        stopCaptureButton.setEnabled(false);

        JButton runAlertTestsButton = new JButton("Run Alert Tests");
        runAlertTestsButton.setToolTipText("Runs controlled test packets through the analyzer and displays results");
        runAlertTestsButton.addActionListener(evt -> runAlertTestsUI());


        JButton exportCsvButton = new JButton("Export CSV");
        exportCsvButton.setToolTipText("Export the current analyzed packet list to a CSV file (for spreadsheet analysis)");
        exportCsvButton.addActionListener(evt -> exportCsv());

        JButton exportJsonlButton = new JButton("Export JSONL");
        exportJsonlButton.setToolTipText("Export the current analyzed packet list to JSON Lines (for research/ML pipelines)");
        exportJsonlButton.addActionListener(evt -> exportJsonl());
        JButton detailedViewButton = new JButton("Detailed View");
        detailedViewButton.setToolTipText("View details and alert explanation for selected packet");
        detailedViewButton.addActionListener(evt -> {
            if (selectedIndex >= 0 && selectedIndex < packets.size()) {
                new PacketDetails(packets, results, selectedIndex, handle).setVisible(true);
                this.setVisible(false);
            } else {
                JOptionPane.showMessageDialog(this, "Please select a packet.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        JButton exitButton = new JButton("Exit");
        exitButton.addActionListener(evt -> System.exit(0));

        startCaptureButton.addActionListener(evt -> startLiveCapture(listModel, startCaptureButton, stopCaptureButton));
        stopCaptureButton.addActionListener(evt -> stopLiveCapture(startCaptureButton, stopCaptureButton));

        buttonPanel.add(loadPcapButton);
        buttonPanel.add(runAlertTestsButton);
        buttonPanel.add(exportCsvButton);
        buttonPanel.add(exportJsonlButton);
        buttonPanel.add(startCaptureButton);
        buttonPanel.add(stopCaptureButton);
        buttonPanel.add(detailedViewButton);
        buttonPanel.add(exitButton);

        footerPanel.add(buttonPanel, BorderLayout.SOUTH);

        add(headerPanel, BorderLayout.NORTH);
        add(mainPanel, BorderLayout.CENTER);
        add(footerPanel, BorderLayout.SOUTH);

        setLocationRelativeTo(null);
        setVisible(true);
    }

    // -------------------- Live Capture --------------------

    private void startLiveCapture(DefaultListModel<String> listModel, JButton startBtn, JButton stopBtn) {
        if (capturing) return;

        if (device == null) {
            JOptionPane.showMessageDialog(this, "No interface selected.", "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        capturing = true;
        telemetry.setCapturing(true);
        startBtn.setEnabled(false);
        stopBtn.setEnabled(true);

        captureThread = new Thread(() -> {
            try {
                int snaplen = 65536;
                int timeout = 150;
                handle = device.openLive(snaplen, PromiscuousMode.PROMISCUOUS, timeout);

                long nextTick = System.currentTimeMillis() + 1000;

                while (capturing && handle != null && handle.isOpen()) {
                    Packet packet;
                    try {
                        packet = handle.getNextPacket(); // null on timeout
                    } catch (NotOpenException e) {
                        break;
                    }

                    if (packet == null) {
                        // still send telemetry once per second even if no packets arrive
                        long now = System.currentTimeMillis();
                        if (now >= nextTick) {
                            telemetry.tick();
                            nextTick = now + 1000;
                        }
                        continue;
                    }

                    // 1) count the packet
                    telemetry.onPacketCaptured();

                    // 2) analyze it (your IDS logic)
                    SuspicionResult r = analyzer.analyze(packet);
                    // only send MEDIUM/HIGH
                    if (r.getSeverity() == com.first.src.analysis.Severity.MEDIUM
                            || r.getSeverity() == com.first.src.analysis.Severity.HIGH) {
                        alertClient.sendAlert(r);
                    }
                    String display = formatDisplayLine(packet, r);

                    // 3) update UI list
                    SwingUtilities.invokeLater(() -> {
                        packets.add(packet);
                        results.add(r);
                        listModel.addElement(display);
                    });

                    // 4) send telemetry once per second
                    long now = System.currentTimeMillis();
                    if (now >= nextTick) {
                        telemetry.tick();
                        nextTick = now + 1000;
                    }
                }


            } catch (Exception e) {
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this, e.getMessage(), "Capture Error", JOptionPane.ERROR_MESSAGE));
            } finally {
                capturing = false;
                SwingUtilities.invokeLater(() -> {
                    startBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                });

                try {
                    if (handle != null && handle.isOpen()) handle.close();
                } catch (Exception ignored) {}
            }
        }, "capture-thread");

        captureThread.start();
    }

    private void stopLiveCapture(JButton startBtn, JButton stopBtn) {
        capturing = false;
        telemetry.setCapturing(false);
        telemetry.tick(); // optional: sends one final update to the web UI

        try {
            if (handle != null && handle.isOpen()) handle.close();
        } catch (Exception ignored) {}

        if (captureThread != null) {
            captureThread.interrupt();
        }

        startBtn.setEnabled(true);
        stopBtn.setEnabled(false);
    }

    // -------------------- PCAP Load --------------------

    private void loadPcap(DefaultListModel<String> listModel) {
        JFileChooser chooser = new JFileChooser();
        int result = chooser.showOpenDialog(this);

        if (result != JFileChooser.APPROVE_OPTION) return;

        var file = chooser.getSelectedFile();

        new Thread(() -> {
            try {
                PcapHandle offlineHandle = Pcaps.openOffline(file.getAbsolutePath());

                PacketListener listener = packet -> SwingUtilities.invokeLater(() -> {
                    SuspicionResult r = analyzer.analyze(packet);
                    // only send MEDIUM/HIGH
                    if (r.getSeverity() == com.first.src.analysis.Severity.MEDIUM
                            || r.getSeverity() == com.first.src.analysis.Severity.HIGH) {
                        alertClient.sendAlert(r);
                    }
                    String display = formatDisplayLine(packet, r);

                    packets.add(packet);
                    results.add(r);
                    listModel.addElement(display);
                });

                offlineHandle.loop(-1, listener);
                offlineHandle.close();

            } catch (Exception e) {
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this, e.getMessage(), "PCAP Load Error", JOptionPane.ERROR_MESSAGE));
            }
        }, "pcap-load-thread").start();
    }

    private String formatDisplayLine(Packet packet, SuspicionResult r) {
        String base = packet.toString();

        String sev = r.getSeverity() != null ? r.getSeverity().name() : "LOW";
        if ("HIGH".equals(sev)) return "[HIGH ALERT] " + base;
        if ("MEDIUM".equals(sev)) return "[MEDIUM ALERT] " + base;

        // still show score for low to help debugging (optional)
        return base;
    }

    // -------------------- Run Alert Tests UI --------------------

    private void runAlertTestsUI() {
        new Thread(() -> {
            String report;
            try {
                report = runControlledAlertTests();
            } catch (Exception ex) {
                report = "Alert test failed:\n\n" + ex.getMessage();
            }
            final String finalReport = report;
            SwingUtilities.invokeLater(() -> showTestResultsDialog(finalReport));
        }, "alert-test-thread").start();
    }

    private void showTestResultsDialog(String report) {
        JTextArea area = new JTextArea(report, 22, 80);
        area.setEditable(false);
        area.setFont(new Font("Consolas", Font.PLAIN, 12));
        area.setCaretPosition(0);

        JScrollPane scroll = new JScrollPane(area);

        JDialog dialog = new JDialog(this, "SeerSniff - Alert Test Results", true);
        dialog.setLayout(new BorderLayout());
        dialog.add(scroll, BorderLayout.CENTER);

        JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton copy = new JButton("Copy");
        copy.addActionListener(e -> {
            area.selectAll();
            area.copy();
            area.setCaretPosition(0);
        });

        JButton close = new JButton("Close");
        close.addActionListener(e -> dialog.dispose());

        bottom.add(copy);
        bottom.add(close);

        dialog.add(bottom, BorderLayout.SOUTH);
        dialog.pack();
        dialog.setLocationRelativeTo(this);
        dialog.setVisible(true);
    }

    private String runControlledAlertTests() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append("=== SeerSniff Controlled Alert Tests ===\n");
        sb.append("Purpose: deterministic validation of alert rules (no PCAP required)\n\n");

        Packet xmas = buildTcpPacket(3389, false, true, true, true, false);
        appendResult(sb, "TCP Xmas Scan (FIN+PSH+URG) -> 3389", xmas);

        Packet nullScan = buildTcpPacket(80, false, false, false, false, false);
        appendResult(sb, "TCP NULL Scan (no flags) -> 80", nullScan);

        Packet finOnly = buildTcpPacket(22, false, true, false, false, false);
        appendResult(sb, "TCP FIN-only Scan -> 22", finOnly);

        Packet synOnly = buildTcpPacket(445, true, false, false, false, false);
        appendResult(sb, "TCP SYN-only -> 445", synOnly);

        Packet udpTo1433 = buildUdpPacket(1433);
        appendResult(sb, "UDP -> 1433", udpTo1433);

        for (int i = 0; i < 25; i++) {
            analyzer.analyze(buildIcmpEchoRequest((short) 1, (short) i));
        }
        Packet icmpFinal = buildIcmpEchoRequest((short) 1, (short) 999);
        appendResult(sb, "ICMP Burst (after 25 rapid ICMP)", icmpFinal);

        sb.append("\n=== End of Tests ===\n");
        sb.append("Tip: screenshot this window for Milestone 2 testing evidence.\n");
        return sb.toString();
    }

    private void appendResult(StringBuilder sb, String label, Packet packet) {
        SuspicionResult r = analyzer.analyze(packet);
        sb.append("--- ").append(label).append(" ---\n");
        sb.append("Score: ").append(r.getScore()).append("\n");
        sb.append("Severity: ").append(r.getSeverity()).append("\n");
        sb.append("Reasons: ").append(r.getReasons()).append("\n\n");
    }

    // -------------------- Packet builders for tests --------------------

    private Packet buildTcpPacket(int destPort,
                                  boolean syn,
                                  boolean fin,
                                  boolean psh,
                                  boolean urg,
                                  boolean ack) throws Exception {

        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.1");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.2");

        TcpPacket.Builder tcpBuilder = new TcpPacket.Builder();
        tcpBuilder
                .srcPort(TcpPort.getInstance((short) 44444))
                .dstPort(TcpPort.getInstance((short) destPort))
                .sequenceNumber(1000)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .urg(urg)
                .ack(ack)
                .psh(psh)
                .rst(false)
                .syn(syn)
                .fin(fin)
                .window((short) 1024)
                .urgentPointer((short) 0)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(tcpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ipBuilder.build();
    }

    private Packet buildUdpPacket(int destPort) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.1");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.2");

        UnknownPacket.Builder payload = new UnknownPacket.Builder()
                .rawData(new byte[]{0x01, 0x02, 0x03});

        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .srcPort(UdpPort.getInstance((short) 55555))
                .dstPort(UdpPort.getInstance((short) destPort))
                .payloadBuilder(payload)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(udpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ipBuilder.build();
    }

    private Packet buildIcmpEchoRequest(short id, short seq) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.1");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.2");

        UnknownPacket.Builder payload = new UnknownPacket.Builder()
                .rawData(new byte[]{9, 8, 7, 6});

        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
        echoBuilder.identifier(id).sequenceNumber(seq).payloadBuilder(payload);

        IcmpV4CommonPacket.Builder icmpBuilder = new IcmpV4CommonPacket.Builder();
        icmpBuilder
                .type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echoBuilder)
                .correctChecksumAtBuild(true);

        IpV4Packet.Builder ipBuilder = new IpV4Packet.Builder();
        ipBuilder
                .version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.ICMPV4)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(icmpBuilder)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ipBuilder.build();
    }


    // =======================
    // Research exports (Sprint 1)
    // =======================

    private void exportCsv() {
        if (packets.isEmpty() || results.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No analyzed packets to export yet.", "Export CSV", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        File f = chooseSaveFile("seer-sniff-export.csv");
        if (f == null) return;

        int n = Math.min(packets.size(), results.size());

        try (BufferedWriter bw = new BufferedWriter(new java.io.OutputStreamWriter(new java.io.FileOutputStream(f), StandardCharsets.UTF_8))) {
            bw.write("index,ts_utc,src_ip,dst_ip,src_port,dst_port,protocol,length,score,severity,reasons,rule_scores_json");
            bw.newLine();

            String ts = Instant.now().toString();
            for (int i = 0; i < n; i++) {
                Packet p = packets.get(i);
                SuspicionResult r = results.get(i);
                PacketMeta m = PacketMeta.from(p);

                String protocol = m.isTcp ? "TCP" : (m.isUdp ? "UDP" : "OTHER");

                String reasons = String.join(" | ", r.getReasons());
                String ruleScoresJson = mapToJsonObject(r.getRuleScores());

                bw.write(i + ","
                        + csv(ts) + ","
                        + csv(m.srcIp) + ","
                        + csv(m.dstIp) + ","
                        + csv(m.srcPort) + ","
                        + csv(m.dstPort) + ","
                        + csv(protocol) + ","
                        + m.length + ","
                        + r.getScore() + ","
                        + csv(r.getSeverity().name()) + ","
                        + csv(reasons) + ","
                        + csv(ruleScoresJson)
                );
                bw.newLine();
            }

            JOptionPane.showMessageDialog(this, "Exported " + n + " records to:\n" + f.getAbsolutePath(),
                    "Export CSV", JOptionPane.INFORMATION_MESSAGE);

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed to export CSV: " + ex.getMessage(),
                    "Export CSV", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void exportJsonl() {
        if (packets.isEmpty() || results.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No analyzed packets to export yet.", "Export JSONL", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        File f = chooseSaveFile("seer-sniff-export.jsonl");
        if (f == null) return;

        int n = Math.min(packets.size(), results.size());

        try (BufferedWriter bw = new BufferedWriter(new java.io.OutputStreamWriter(new java.io.FileOutputStream(f), StandardCharsets.UTF_8))) {
            String ts = Instant.now().toString();

            for (int i = 0; i < n; i++) {
                Packet p = packets.get(i);
                SuspicionResult r = results.get(i);
                PacketMeta m = PacketMeta.from(p);

                String protocol = m.isTcp ? "TCP" : (m.isUdp ? "UDP" : "OTHER");

                String json = "{"
                        + "\"index\":" + i + ","
                        + "\"ts_utc\":" + json(ts) + ","
                        + "\"meta\":{"
                        + "\"src_ip\":" + json(m.srcIp) + ","
                        + "\"dst_ip\":" + json(m.dstIp) + ","
                        + "\"src_port\":" + json(m.srcPort) + ","
                        + "\"dst_port\":" + json(m.dstPort) + ","
                        + "\"protocol\":" + json(protocol) + ","
                        + "\"length\":" + m.length
                        + "},"
                        + "\"result\":{"
                        + "\"score\":" + r.getScore() + ","
                        + "\"severity\":" + json(r.getSeverity().name()) + ","
                        + "\"reasons\":" + listToJsonArray(r.getReasons()) + ","
                        + "\"rule_scores\":" + mapToJsonObject(r.getRuleScores())
                        + "}"
                        + "}";

                bw.write(json);
                bw.newLine();
            }

            JOptionPane.showMessageDialog(this, "Exported " + n + " records to:\n" + f.getAbsolutePath(),
                    "Export JSONL", JOptionPane.INFORMATION_MESSAGE);

        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Failed to export JSONL: " + ex.getMessage(),
                    "Export JSONL", JOptionPane.ERROR_MESSAGE);
        }
    }

    private File chooseSaveFile(String defaultName) {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(defaultName));
        int res = chooser.showSaveDialog(this);
        if (res != JFileChooser.APPROVE_OPTION) return null;
        return chooser.getSelectedFile();
    }

    private static String csv(Object o) {
        if (o == null) return "\"\"";
        String s = String.valueOf(o);
        s = s.replace("\"", "\"\""); // escape internal quotes
        return "\"" + s + "\"";
    }

    private static String json(Object o) {
        if (o == null) return "null";
        String s = String.valueOf(o);
        return "\"" + escapeJson(s) + "\"";
    }

    private static String escapeJson(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> sb.append("\\\\");
                case '"' -> sb.append("\\\"");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    private static String listToJsonArray(List<String> items) {
        if (items == null || items.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) sb.append(",");
            sb.append(json(items.get(i)));
        }
        sb.append("]");
        return sb.toString();
    }

    private static String mapToJsonObject(Map<String, Integer> m) {
        if (m == null || m.isEmpty()) return "{}";
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Integer> e : m.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append(json(e.getKey())).append(":").append(e.getValue() == null ? 0 : e.getValue());
        }
        sb.append("}");
        return sb.toString();
    }

}