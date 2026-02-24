package com.first.src;

import com.first.src.analysis.*;
import com.first.src.analysis.rules.*;

import java.util.List;

public class ExperimentDriver {

    public static void main(String[] args) throws Exception {

        if (args.length == 0) {
            System.out.println("Usage: java ExperimentDriver <pcap-file>");
            return;
        }

        String pcapPath = args[0];

        ExperimentConfig config = new ExperimentConfig(
                List.of(
                        new TcpScanFlagRule(),
                        new TcpPortScanBurstRule(),
                        new TcpRstBurstRule(),
                        new UdpPortFanoutRule(),
                        new HighRiskPortRule(),
                        new IcmpBurstRule()
                ),
                70,   // HIGH threshold
                45,   // MEDIUM threshold
                "baseline_behavioral_test"
        );

        ExperimentRunner.runExperiment(pcapPath, config);
    }
}