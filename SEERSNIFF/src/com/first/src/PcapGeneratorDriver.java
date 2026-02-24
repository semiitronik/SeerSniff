package com.first.src;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.*;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;

public class PcapGeneratorDriver {

    public static void main(String[] args) throws Exception {

        String out = (args.length > 0) ? args[0] : "sample_all_alerts.pcap";

        int snapLen = 65536;
        // EN10MB is fine for offline dumping unless you have a strict reason to use another
        PcapHandle dead = Pcaps.openDead(DataLinkType.EN10MB, snapLen);
        PcapDumper dumper = dead.dumpOpen(out);

        System.out.println("Writing PCAP: " + out);

        // Build deterministic packets
        Packet xmas = buildTcpPacket(3389, false, true, true, true, false, false); // FIN+PSH+URG
        Packet nullScan = buildTcpPacket(80, false, false, false, false, false, false); // no flags
        Packet finOnly = buildTcpPacket(22, false, true, false, false, false, false); // FIN only
        Packet synOnly445 = buildTcpPacket(445, true, false, false, false, false, false); // SYN only -> SMB
        Packet rstPacket = buildTcpPacket(445, false, false, false, false, false, true); // RST spike packet

        Packet udpTo1433 = buildUdpPacket(1433);

        // ICMP burst (echo requests)
        Packet[] icmpBurst = new Packet[30];
        for (int i = 0; i < icmpBurst.length; i++) {
            icmpBurst[i] = buildIcmpEchoRequest((short) 1, (short) i);
        }

        // --- Dump a baseline + obvious scan flags ---
        dump(dumper, xmas);
        dump(dumper, nullScan);
        dump(dumper, finOnly);
        dump(dumper, synOnly445);
        dump(dumper, udpTo1433);

        // --- Trigger TcpPortScanBurstRule: SYN to many unique ports quickly ---
        // Choose ports that include high-risk ones too to increase correlation value.
        int[] scanPorts = new int[] { 20,21,22,23,25,53,80,110,111,135,139,143,389,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,9200,27017 };
        for (int p : scanPorts) {
            dump(dumper, buildTcpPacket(p, true, false, false, false, false, false)); // SYN only
        }

        // --- Trigger TcpRstBurstRule: lots of RST quickly ---
        for (int i = 0; i < 35; i++) {
            dump(dumper, rstPacket);
        }

        // --- Trigger UdpPortFanoutRule: UDP to many ports quickly ---
        for (int p = 10000; p < 10000 + 40; p++) {
            dump(dumper, buildUdpPacket(p));
        }

        // --- Trigger IcmpBurstRule: 30 echo requests quickly ---
        for (Packet p : icmpBurst) {
            dump(dumper, p);
        }

        dumper.close();
        dead.close();

        System.out.println("Done. Generated: " + out);
    }

    private static void dump(PcapDumper dumper, Packet packet) throws Exception {
        // timestamp doesn’t matter much for your System.currentTimeMillis()-based rules,
        // but PcapDumper wants one.
        dumper.dump(packet, new Timestamp(System.currentTimeMillis()));
    }

    private static Packet buildTcpPacket(int destPort,
                                         boolean syn,
                                         boolean fin,
                                         boolean psh,
                                         boolean urg,
                                         boolean ack,
                                         boolean rst) throws Exception {

        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.10");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.20");

        TcpPacket.Builder tcp = new TcpPacket.Builder();
        tcp.srcPort(TcpPort.getInstance((short) 44444))
                .dstPort(TcpPort.getInstance((short) destPort))
                .sequenceNumber(1000)
                .acknowledgmentNumber(0)
                .dataOffset((byte) 5)
                .reserved((byte) 0)
                .urg(urg)
                .ack(ack)
                .psh(psh)
                .rst(rst)
                .syn(syn)
                .fin(fin)
                .window((short) 1024)
                .urgentPointer((short) 0)
                .srcAddr(src)
                .dstAddr(dst)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ip = new IpV4Packet.Builder();
        ip.version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.TCP)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(tcp)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ip.build();
    }

    private static Packet buildUdpPacket(int destPort) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.10");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.20");

        UnknownPacket.Builder payload = new UnknownPacket.Builder()
                .rawData(new byte[]{0x01, 0x02, 0x03});

        UdpPacket.Builder udp = new UdpPacket.Builder();
        udp.srcPort(UdpPort.getInstance((short) 55555))
                .dstPort(UdpPort.getInstance((short) destPort))
                .payloadBuilder(payload)

                // ✅ REQUIRED for checksum pseudo-header in Pcap4J 1.8.2
                .srcAddr(src)
                .dstAddr(dst)

                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        IpV4Packet.Builder ip = new IpV4Packet.Builder();
        ip.version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.UDP)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(udp)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ip.build();
    }

    private static Packet buildIcmpEchoRequest(short id, short seq) throws Exception {
        Inet4Address src = (Inet4Address) InetAddress.getByName("192.168.1.10");
        Inet4Address dst = (Inet4Address) InetAddress.getByName("192.168.1.20");

        UnknownPacket.Builder payload = new UnknownPacket.Builder().rawData(new byte[]{9, 8, 7, 6});

        IcmpV4EchoPacket.Builder echo = new IcmpV4EchoPacket.Builder();
        echo.identifier(id)
                .sequenceNumber(seq)
                .payloadBuilder(payload);

        IcmpV4CommonPacket.Builder icmp = new IcmpV4CommonPacket.Builder();
        icmp.type(IcmpV4Type.ECHO)
                .code(IcmpV4Code.NO_CODE)
                .payloadBuilder(echo)
                .correctChecksumAtBuild(true);

        IpV4Packet.Builder ip = new IpV4Packet.Builder();
        ip.version(IpVersion.IPV4)
                .tos(IpV4Rfc791Tos.newInstance((byte) 0))
                .ttl((byte) 64)
                .protocol(IpNumber.ICMPV4)
                .srcAddr(src)
                .dstAddr(dst)
                .payloadBuilder(icmp)
                .correctChecksumAtBuild(true)
                .correctLengthAtBuild(true);

        return ip.build();
    }
}