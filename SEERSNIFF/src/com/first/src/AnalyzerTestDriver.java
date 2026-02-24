package com.first.src;

import com.first.src.analysis.PacketAnalyzer;
import com.first.src.analysis.SuspicionResult;
import com.first.src.analysis.rules.HighRiskPortRule;
import com.first.src.analysis.rules.IcmpBurstRule;
import com.first.src.analysis.rules.TcpScanFlagRule;
import com.first.src.analysis.rules.TcpPortScanBurstRule;
import com.first.src.analysis.rules.TcpRstBurstRule;
import com.first.src.analysis.rules.UdpPortFanoutRule;

import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.List;

/**
 * AnalyzerTestDriver
 *
 * Purpose:
 * - Deterministically validates SeerSniff alert logic without needing a special PCAP.
 * - Constructs packets in memory (TCP scan patterns, high-risk ports, ICMP burst)
 *   and runs them through PacketAnalyzer.
 * - Provides repeatable "Initial Testing" evidence.
 * - Proves suspicious packet identification works independent of capture/PCAP quirks.
 */
public class AnalyzerTestDriver {

    public static void main(String[] args) throws Exception {

        PacketAnalyzer analyzer = new PacketAnalyzer(List.of(
                new TcpScanFlagRule(),
                new HighRiskPortRule(),
                new IcmpBurstRule()
        ));

        System.out.println("=== Running Controlled Analyzer Tests ===");

        // 1) TCP Xmas scan-like packet: FIN + PSH + URG (common scan signature)
        Packet xmas = buildTcpPacket(
                3389, // RDP (also a high-risk port in your rule set)
                false, // syn
                true,  // fin
                true,  // psh
                true,  // urg
                false  // ack
        );
        printResult("TCP Xmas Scan (FIN+PSH+URG) to 3389", analyzer, xmas);

        // 2) TCP NULL scan-like packet: no flags set
        Packet nullScan = buildTcpPacket(
                80,
                false, false, false, false, false
        );
        printResult("TCP NULL Scan (no flags) to 80", analyzer, nullScan);

        // 3) TCP FIN-only scan-like packet
        Packet finOnly = buildTcpPacket(
                22,
                false, true, false, false, false
        );
        printResult("TCP FIN-only Scan to 22", analyzer, finOnly);

        // 4) TCP SYN-only (often benign, but your rule flags it moderately)
        Packet synOnly = buildTcpPacket(
                445, // SMB (high-risk)
                true, false, false, false, false
        );
        printResult("TCP SYN-only to 445", analyzer, synOnly);

        // 5) UDP to a high-risk port (e.g., 1433) to trigger HighRiskPortRule
        Packet udpTo1433 = buildUdpPacket(1433);
        printResult("UDP packet to 1433", analyzer, udpTo1433);

        // 6) ICMP burst: feed 25 ICMP packets quickly, then test one more
        // NOTE: Your IcmpBurstRule uses System.currentTimeMillis(), so this triggers reliably.
        for (int i = 0; i < 25; i++) {
            analyzer.analyze(buildIcmpEchoRequest((short) 1, (short) i));
        }
        Packet icmpFinal = buildIcmpEchoRequest((short) 1, (short) 999);
        printResult("ICMP Burst (after 25 rapid ICMP packets)", analyzer, icmpFinal);

        System.out.println("\n=== Test Complete ===");
    }

    private static void printResult(String label, PacketAnalyzer analyzer, Packet packet) {
        SuspicionResult result = analyzer.analyze(packet);

        System.out.println("\n--- Test: " + label + " ---");
        System.out.println("Score: " + result.getScore());
        System.out.println("Severity: " + result.getSeverity());
        System.out.println("Reasons: " + result.getReasons());
    }

    /**
     * Builds a minimal TCP-over-IPv4 packet with specific flag bits.
     *
     * IMPORTANT for Pcap4J 1.8.2:
     * - If correctChecksumAtBuild(true) is set, TCP builder MUST know src/dst IPs
     *   (pseudo-header checksum). That is why we set tcpBuilder.srcAddr/dstAddr.
     */
    private static Packet buildTcpPacket(int destPort,
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
                .dataOffset((byte) 5)     // minimum header length
                .reserved((byte) 0)
                .urg(urg)
                .ack(ack)
                .psh(psh)
                .rst(false)
                .syn(syn)
                .fin(fin)
                .window((short) 1024)
                .urgentPointer((short) 0)
                // Required for TCP checksum pseudo-header in Pcap4J 1.8.2
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

    /**
     * Builds a minimal UDP-over-IPv4 packet (useful for testing HighRiskPortRule on UDP).
     */
    private static Packet buildUdpPacket(int destPort) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.1");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.2");

        UnknownPacket.Builder payload = new UnknownPacket.Builder().rawData(new byte[]{0x01, 0x02, 0x03});

        UdpPacket.Builder udpBuilder = new UdpPacket.Builder();
        udpBuilder
                .srcPort(UdpPort.getInstance((short) 55555))
                .dstPort(UdpPort.getInstance((short) destPort))
                .payloadBuilder(payload)
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

    /**
     * Builds an ICMPv4 Echo Request (ping).
     */
    private static Packet buildIcmpEchoRequest(short id, short seq) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.1");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.2");

        UnknownPacket.Builder payload = new UnknownPacket.Builder().rawData(new byte[]{9, 8, 7, 6});

        IcmpV4EchoPacket.Builder echoBuilder = new IcmpV4EchoPacket.Builder();
        echoBuilder
                .identifier(id)
                .sequenceNumber(seq)
                .payloadBuilder(payload);

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
}