package com.first.src.analysis;

import org.pcap4j.packet.Packet;
import java.util.List;

public interface SuspicionRule {
    int score(Packet packet, AnalysisContext ctx);
    void explain(Packet packet, AnalysisContext ctx, List<String> outReasons);
    default String name() { return getClass().getSimpleName(); }
}