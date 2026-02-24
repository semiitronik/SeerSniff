package com.first.src;

import com.first.src.analysis.PacketAnalyzer;
import com.first.src.analysis.SuspicionResult;
import com.first.src.analysis.SuspicionRule;
import com.first.src.analysis.rules.*;
import org.pcap4j.core.Pcaps;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.packet.Packet;

import java.util.List;

/**
 * AnalyzerDriver is a simple milestone test harness.
 * It validates the core pipeline: load packets -> analyze -> print results.
 */
public class AnalyzerDriver {

    public static void main(String[] args) {
        List<SuspicionRule> rules = List.of(
                new TcpScanFlagRule(),
                new TcpPortScanBurstRule(),
                new TcpRstBurstRule(),
                new UdpPortFanoutRule(),
                new HighRiskPortRule(),
                new IcmpBurstRule()
        );

        PacketAnalyzer analyzer = new PacketAnalyzer(rules);

        // OPTION A: Run against a pcap file if provided
        if (args.length > 0) {
            runOnPcap(args[0], analyzer);
            return;
        }

        // OPTION B: If no pcap provided, just prove setup succeeds
        System.out.println("AnalyzerDriver ran successfully.");
        System.out.println("Tip: Provide a pcap path argument to analyze packets.");
        System.out.println("Example: java ... com.first.src.AnalyzerDriver sample.pcap");
    }

    private static void runOnPcap(String pcapPath, PacketAnalyzer analyzer) {
        System.out.println("Loading PCAP: " + pcapPath);

        try (PcapHandle handle = Pcaps.openOffline(pcapPath)) {
            int count = 0;

            while (true) {
                Packet packet = handle.getNextPacket();
                if (packet == null) break;

                SuspicionResult sr = analyzer.analyze(packet);

                // Only print suspicious packets to keep output readable
                if (sr.isSuspicious()) {
                    System.out.println("---- Suspicious Packet #" + (++count) + " ----");
                    System.out.println("Length: " + packet.length());
                    System.out.println("Risk: " + sr.getScore() + " Severity: " + sr.getSeverity());
                    System.out.println("Reasons: " + sr.getReasons());
                    System.out.println(packet);
                }
            }

            System.out.println("Done. Suspicious printed: " + count);
        } catch (Exception e) {
            System.err.println("Failed to analyze pcap: " + e.getMessage());
            e.printStackTrace();
        }
    }

}