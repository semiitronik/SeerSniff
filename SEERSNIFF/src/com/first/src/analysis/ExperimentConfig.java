package com.first.src.analysis;

import java.util.List;

public class ExperimentConfig {

    public final List<SuspicionRule> rules;
    public final int highThreshold;
    public final int mediumThreshold;
    public final String experimentName;

    public ExperimentConfig(List<SuspicionRule> rules,
                            int highThreshold,
                            int mediumThreshold,
                            String experimentName) {
        this.rules = rules;
        this.highThreshold = highThreshold;
        this.mediumThreshold = mediumThreshold;
        this.experimentName = experimentName;
    }
}