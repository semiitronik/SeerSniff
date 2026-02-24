package com.first.src.analysis;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.util.*;

public class ExperimentRunner {

    public static void runExperiment(String pcapPath, ExperimentConfig config) throws Exception {

        PacketAnalyzer analyzer = new PacketAnalyzer(config.rules);
        ExperimentSummary summary = new ExperimentSummary();

        String timestamp = LocalDateTime.now().toString().replace(":", "-");
        Path outputDir = Paths.get("experiments",
                config.experimentName + "_" + timestamp);
        Files.createDirectories(outputDir);

        BufferedWriter jsonlWriter = Files.newBufferedWriter(outputDir.resolve("alerts.jsonl"));
        BufferedWriter csvWriter = Files.newBufferedWriter(outputDir.resolve("features.csv"));

        csvWriter.write("src_ip,dst_ip,src_port,dst_port,protocol,length,score,severity\n");

        PcapHandle handle = Pcaps.openOffline(pcapPath);

        Packet packet;
        while ((packet = handle.getNextPacket()) != null) {

            summary.totalPackets++;

            SuspicionResult result = analyzer.analyze(packet);
            PacketMeta meta = PacketMeta.from(packet);

            // Track severity counts
            switch (result.getSeverity()) {
                case HIGH -> summary.highAlerts++;
                case MEDIUM -> summary.mediumAlerts++;
                default -> summary.lowAlerts++;
            }

            // Track rule triggers
            result.getRuleScores().forEach((rule, score) -> {
                if (score > 0) summary.incrementRule(rule);
            });

            if (meta.srcIp != null)
                summary.srcIpCounts.merge(meta.srcIp, 1, Integer::sum);

            if (meta.dstPort != null)
                summary.dstPortCounts.merge(meta.dstPort, 1, Integer::sum);

            // JSONL
            jsonlWriter.write(toJsonLine(meta, result));
            jsonlWriter.newLine();

            // CSV
            csvWriter.write(csv(meta.srcIp) + ","
                    + csv(meta.dstIp) + ","
                    + csv(meta.srcPort) + ","
                    + csv(meta.dstPort) + ","
                    + csv(meta.isTcp ? "TCP" : meta.isUdp ? "UDP" : "OTHER") + ","
                    + meta.length + ","
                    + result.getScore() + ","
                    + result.getSeverity());
            csvWriter.newLine();
        }

        handle.close();
        jsonlWriter.close();
        csvWriter.close();

        writeSummaryJson(summary, outputDir.resolve("run_summary.json"));

        System.out.println("Experiment complete.");
        System.out.println("Output directory: " + outputDir.toAbsolutePath());
    }

    private static String csv(Object o) {
        if (o == null) return "\"\"";
        String s = String.valueOf(o);
        return "\"" + s.replace("\"", "\"\"") + "\"";
    }

    private static String toJsonLine(PacketMeta meta, SuspicionResult result) {
        return "{"
                + "\"src_ip\":\"" + meta.srcIp + "\","
                + "\"dst_ip\":\"" + meta.dstIp + "\","
                + "\"dst_port\":" + meta.dstPort + ","
                + "\"score\":" + result.getScore() + ","
                + "\"severity\":\"" + result.getSeverity() + "\""
                + "}";
    }

    private static void writeSummaryJson(ExperimentSummary summary, Path path) throws IOException {
        try (BufferedWriter writer = Files.newBufferedWriter(path)) {
            writer.write("{\n");
            writer.write("\"total_packets\":" + summary.totalPackets + ",\n");
            writer.write("\"high_alerts\":" + summary.highAlerts + ",\n");
            writer.write("\"medium_alerts\":" + summary.mediumAlerts + ",\n");
            writer.write("\"low_alerts\":" + summary.lowAlerts + "\n");
            writer.write("}");
        }
    }
}