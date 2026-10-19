package com.logssey.iacworker.analysis;

import java.util.List;

import software.amazon.awssdk.services.iam.IamClient;

/** iam:SimulateCustomPolicy 만 쓴다 (읽기 전용). 계정의 실제 정책을 바꾸지 않고 문서만 평가한다. */
public class AwsIamSimulator implements IamSimulator {

    private final IamClient client;

    public AwsIamSimulator(IamClient client) {
        this.client = client;
    }

    @Override
    public String decide(List<String> policyDocuments, String action, String resourceArn) {
        if (policyDocuments.isEmpty()) {
            return "implicitDeny";
        }
        var response = client.simulateCustomPolicy(request -> request.policyInputList(policyDocuments)
                .actionNames(action).resourceArns(resourceArn));
        return response.evaluationResults().getFirst().evalDecisionAsString();
    }
}
