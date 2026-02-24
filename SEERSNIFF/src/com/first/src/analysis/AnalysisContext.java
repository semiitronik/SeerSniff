package com.first.src.analysis;

import java.util.*;

public class AnalysisContext {

    // ---- time windows keyed by src IP ----
    private final Map<String, Deque<Long>> icmpEchoBySrc = new HashMap<>();

    // Port scan: src -> (timestamp queue of SYN events) + set of dst ports seen in window
    private final Map<String, Deque<Long>> synTimesBySrc = new HashMap<>();
    private final Map<String, Map<Integer, Long>> synPortLastSeenBySrc = new HashMap<>();

    // Failed handshake heuristic: src -> recent RST timestamps (often happens when scanning closed ports)
    private final Map<String, Deque<Long>> rstTimesBySrc = new HashMap<>();

    // UDP fanout: src -> recent udp timestamps + distinct dst ports in window
    private final Map<String, Deque<Long>> udpTimesBySrc = new HashMap<>();
    private final Map<String, Map<Integer, Long>> udpPortLastSeenBySrc = new HashMap<>();

    public Deque<Long> icmpWindow(String srcIp) {
        return icmpEchoBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Deque<Long> synTimeWindow(String srcIp) {
        return synTimesBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Map<Integer, Long> synPortsWindow(String srcIp) {
        return synPortLastSeenBySrc.computeIfAbsent(srcIp, k -> new HashMap<>());
    }

    public Deque<Long> rstWindow(String srcIp) {
        return rstTimesBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Deque<Long> udpTimeWindow(String srcIp) {
        return udpTimesBySrc.computeIfAbsent(srcIp, k -> new ArrayDeque<>());
    }

    public Map<Integer, Long> udpPortsWindow(String srcIp) {
        return udpPortLastSeenBySrc.computeIfAbsent(srcIp, k -> new HashMap<>());
    }

    // Utility: evict old timestamps from a deque
    public static void evictOld(Deque<Long> q, long now, long windowMillis) {
        while (!q.isEmpty() && (now - q.peekFirst()) > windowMillis) q.removeFirst();
    }

    // Utility: evict old entries from (value = lastSeenMillis) maps
    public static void evictOld(Map<Integer, Long> lastSeen, long now, long windowMillis) {
        lastSeen.entrySet().removeIf(e -> (now - e.getValue()) > windowMillis);
    }
    private long currentPacketTime = -1;

    public void setCurrentPacketTime(long ts) {
        this.currentPacketTime = ts;
    }

    public long getCurrentPacketTime() {
        if (currentPacketTime > 0) return currentPacketTime;
        return System.currentTimeMillis(); // fallback for safety
    }
}
