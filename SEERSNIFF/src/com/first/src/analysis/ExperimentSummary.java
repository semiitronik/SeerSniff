package com.first.src.analysis;

import java.util.HashMap;
import java.util.Map;

public class ExperimentSummary {

    public int totalPackets = 0;
    public int highAlerts = 0;
    public int mediumAlerts = 0;
    public int lowAlerts = 0;

    public Map<String, Integer> ruleTriggerCounts = new HashMap<>();
    public Map<String, Integer> srcIpCounts = new HashMap<>();
    public Map<Integer, Integer> dstPortCounts = new HashMap<>();

    public void incrementRule(String ruleName) {
        ruleTriggerCounts.merge(ruleName, 1, Integer::sum);
    }
}