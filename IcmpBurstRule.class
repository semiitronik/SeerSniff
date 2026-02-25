package com.first.src;

import com.formdev.flatlaf.FlatLightLaf;
import com.first.src.analysis.SuspicionResult;

import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import java.awt.*;
import java.util.List;

public class PacketDetails extends JFrame {

    private final PcapHandle ha;
    private final List<Packet> p;
    private final List<SuspicionResult> results;
    private final int index;

    private JLabel packetHeaderLabel;

    // ✅ New constructor used by ViewPackets
    public PacketDetails(List<Packet> p, List<SuspicionResult> results, int index, PcapHandle handle) {
        try { UIManager.setLookAndFeel(new FlatLightLaf()); } catch (Exception ignored) {}

        this.p = p;
        this.results = results;
        this.index = index;
        this.ha = handle;

        initComponents();
        loadPacketHeader();
    }

    // Optional compatibility constructor (won’t break older calls)
    public PacketDetails(List<Packet> packets, int index, PcapHandle handle) {
        this(packets, null, index, handle);
    }

    private void initComponents() {
        setTitle("Packet Details");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setSize(900, 600);
        setLayout(new BorderLayout());

        // Header
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(240, 240, 240));

        JLabel title = new JLabel("PACKET DETAILS", SwingConstants.CENTER);
        title.setFont(new Font("Arial", Font.BOLD, 24));
        title.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        headerPanel.add(title, BorderLayout.NORTH);

        packetHeaderLabel = new JLabel("", SwingConstants.CENTER);
        packetHeaderLabel.setFont(new Font("Arial", Font.PLAIN, 14));
        packetHeaderLabel.setBorder(BorderFactory.createTitledBorder("Packet Header"));
        headerPanel.add(packetHeaderLabel, BorderLayout.SOUTH);

        add(headerPanel, BorderLayout.NORTH);

        // Buttons (keep your existing navigation)
        JPanel buttonPanel = new JPanel(new GridLayout(2, 3, 15, 15));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JButton headerButton = new JButton("Get Packet Header");
        headerButton.addActionListener(evt -> {
            new Header(p, index, ha).setVisible(true);
            setVisible(false);
        });

        JButton rawDataButton = new JButton("Get Packet Raw Data");
        rawDataButton.addActionListener(evt -> {
            new RawData(p, index, ha).setVisible(true);
            setVisible(false);
        });

        JButton payloadButton = new JButton("Get Packet Payload");
        payloadButton.addActionListener(evt -> {
            new Payload(p, index, ha).setVisible(true);
            setVisible(false);
        });

        JButton lengthButton = new JButton("Get Packet Length");
        lengthButton.addActionListener(evt -> {
            new Length(p, index, ha).setVisible(true);
            setVisible(false);
        });

        JButton statsButton = new JButton("Check Statistics");
        statsButton.addActionListener(evt -> {
            new CheckStats(p, index, ha).setVisible(true);
            setVisible(false);
        });

        JButton dumpButton = new JButton("Dump Packets");
        dumpButton.addActionListener(evt -> dumpPackets());

        buttonPanel.add(headerButton);
        buttonPanel.add(rawDataButton);
        buttonPanel.add(payloadButton);
        buttonPanel.add(lengthButton);
        buttonPanel.add(statsButton);
        buttonPanel.add(dumpButton);

        add(buttonPanel, BorderLayout.CENTER);

        // ✅ Alert Explanation panel at the bottom
        add(buildAlertPanel(), BorderLayout.SOUTH);

        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void loadPacketHeader() {
        if (index >= 0 && index < p.size()) {
            packetHeaderLabel.setText(String.valueOf(p.get(index).getHeader()));
        } else {
            packetHeaderLabel.setText("No packet selected.");
        }
    }

    private JPanel buildAlertPanel() {
        JPanel alertPanel = new JPanel(new BorderLayout());
        alertPanel.setBorder(BorderFactory.createTitledBorder("Alert Explanation"));

        SuspicionResult r = (results != null && index >= 0 && index < results.size())
                ? results.get(index)
                : null;

        String headerText = (r == null)
                ? "No analysis available for this packet."
                : ("Severity: " + r.getSeverity() + " | Score: " + r.getScore());

        JLabel alertHeader = new JLabel(headerText);
        alertHeader.setBorder(BorderFactory.createEmptyBorder(5, 8, 5, 8));
        alertPanel.add(alertHeader, BorderLayout.NORTH);

        DefaultListModel<String> reasonsModel = new DefaultListModel<>();
        if (r != null && r.getReasons() != null && !r.getReasons().isEmpty()) {
            for (String reason : r.getReasons()) reasonsModel.addElement(reason);
        } else {
            reasonsModel.addElement("No reasons recorded.");
        }

        JList<String> reasonsList = new JList<>(reasonsModel);
        alertPanel.add(new JScrollPane(reasonsList), BorderLayout.CENTER);

        return alertPanel;
    }

    private void dumpPackets() {
        if (ha == null) {
            JOptionPane.showMessageDialog(this, "No capture handle available.", "Dump Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save PCAP Dump");
        int choice = chooser.showSaveDialog(this);
        if (choice != JFileChooser.APPROVE_OPTION) return;

        String path = chooser.getSelectedFile().getAbsolutePath();
        if (!path.toLowerCase().endsWith(".pcap")) path += ".pcap";

        try {
            PcapDumper dumper = ha.dumpOpen(path);
            for (Packet packet : p) {
                dumper.dump(packet, ha.getTimestamp());
            }
            dumper.close();
            JOptionPane.showMessageDialog(this, "Dumped to: " + path, "Success", JOptionPane.INFORMATION_MESSAGE);
        } catch (PcapNativeException | NotOpenException e) {
            JOptionPane.showMessageDialog(this, e.getMessage(), "Dump Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}