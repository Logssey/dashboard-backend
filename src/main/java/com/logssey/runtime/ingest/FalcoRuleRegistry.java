package com.logssey.runtime.ingest;

import java.util.Map;
import java.util.Optional;

import com.logssey.runtime.ingest.RuntimeRuleDefinition.ValidationProfile;

import org.springframework.stereotype.Component;

/** Immutable allow-list translating sensor rule names to the dashboard's stable rule contract. */
@Component
public class FalcoRuleRegistry {

    private static final RuntimeRuleDefinition RUN_001 = new RuntimeRuleDefinition(
            "RUN-001", "컨테이너 셸 실행", "1.0.0", "PROCESS_EXEC", "PROCESS",
            ValidationProfile.CONTAINER_SHELL);
    private static final RuntimeRuleDefinition RUN_003 = new RuntimeRuleDefinition(
            "RUN-003", "ServiceAccount 토큰 접근", "1.0.0", "FILE_ACCESS", "FILE",
            ValidationProfile.SERVICE_ACCOUNT_TOKEN_ACCESS);
    private static final RuntimeRuleDefinition RUN_004 = new RuntimeRuleDefinition(
            "RUN-004", "실행 중인 컨테이너의 패키지 관리자 실행", "1.0.0", "PROCESS_EXEC", "PROCESS",
            ValidationProfile.PACKAGE_MANAGER_EXECUTION);
    private static final RuntimeRuleDefinition RUN_007 = new RuntimeRuleDefinition(
            "RUN-007", "컨테이너 민감 경로 변경", "1.0.0", "FILE_WRITE", "FILE",
            ValidationProfile.SENSITIVE_PATH_WRITE);

    private final Map<String, RuntimeRuleDefinition> rules = Map.of(
            "Logssey RUN-001 Container Shell", RUN_001,
            "Terminal shell in container", RUN_001,
            "Logssey RUN-003 ServiceAccount Token Access", RUN_003,
            "Logssey RUN-004 Package Manager Execution", RUN_004,
            "Logssey RUN-007 Sensitive Path Write", RUN_007);

    public Optional<RuntimeRuleDefinition> find(String sourceRule) {
        return Optional.ofNullable(rules.get(sourceRule));
    }
}
