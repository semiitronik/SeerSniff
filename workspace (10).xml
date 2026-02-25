package com.first.src;

import com.formdev.flatlaf.FlatLightLaf;
import com.first.src.analysis.SuspicionResult;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class CheckStats extends JFrame {

    private PcapHandle ha = null;
    private List<Packet> p1 = new ArrayList<>();
    private List<SuspicionResult> r1 = new ArrayList<>();
    private int i;

    private JList<String> jList1;

    // ✅ Updated constructor: accepts packets + results + index + handle
    public CheckStats(List<Packet> p, List<SuspicionResult> results, int index, PcapHandle handle) {
        try {
            UIManager.setLookAndFeel(new FlatLightLaf());
        } catch (Exception ex) {
            System.err.println("Failed to initialize FlatLaf");
        }

        this.p1 = (p != null) ? p : new ArrayList<>();
        this.r1 = (results != null) ? results : new ArrayList<>();
        this.i = index;
        this.ha = handle;

        initComponents();
        populateStatistics();
    }

    // ✅ Optional compatibility constructor (if anything still calls the old one)
    public CheckStats(List<Packet> p, int index, PcapHandle handle) {
        this(p, null, index, handle);
    }

    private void populateStatistics() {
        DefaultListModel<String> model = new DefaultListModel<>();

        // Show basic packet list stats even if handle is null/offline
        model.addElement("Packets in Memory: " + p1.size());
        model.addElement("Selected Index: " + i);

        // Live capture stats require an open handle
        if (ha == null) {
            model.addElement("Capture Handle: null (PCAP load or no live capture)");
            jList1.setModel(model);
            return;
        }

        try {
            PcapStat stat = ha.getStats();
            model.addElement("Packets Received (pcap stats): " + stat.getNumPacketsReceived());
            model.addElement("Packets Dropped (pcap stats): " + stat.getNumPacketsDropped());
            model.addElement("Dropped by Interface (pcap stats): " + stat.getNumPacketsDroppedByIf());
            jList1.setModel(model);
        } catch (PcapNativeException | NotOpenException e) {
            model.addElement("Error fetching statistics: " + e.getMessage());
            jList1.setModel(model);
        }
    }

    private void initComponents() {
        setTitle("Packet Statistics");
        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        setSize(500, 400);
        setLayout(new BorderLayout());

        // Header Panel
        JPanel headerPanel = new JPanel(new BorderLayout());
        headerPanel.setBackground(new Color(240, 240, 240));

        JLabel headerLabel = new JLabel("STATISTICS", SwingConstants.CENTER);
        headerLabel.setFont(new Font("Arial", Font.BOLD, 24));
        headerLabel.setForeground(new Color(50, 50, 50));
        headerLabel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        headerPanel.add(headerLabel, BorderLayout.CENTER);

        // Statistics List
        jList1 = new JList<>();
        JScrollPane scrollPane = new JScrollPane(jList1);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Packet Statistics"));

        // Footer Panel
        JPanel footerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));

        JButton backButton = new JButton("Back");
        backButton.setToolTipText("Return to Packet Details");
        backButton.addActionListener(evt -> {
            new PacketDetails(p1, r1, i, ha).setVisible(true);
            this.setVisible(false);
        });

        footerPanel.add(backButton);

        // Add Panels to Frame
        add(headerPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        add(footerPanel, BorderLayout.SOUTH);

        setLocationRelativeTo(null);
        setVisible(true);
    }

    public static void main(String args[]) {
        SwingUtilities.invokeLater(() -> new CheckStats(new ArrayList<>(), new ArrayList<>(), 0, null).setVisible(true));
    }
}