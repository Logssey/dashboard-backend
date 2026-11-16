package com.logssey.secret.response;

import java.util.List;
import java.util.Map;
import java.util.Set;

final class SecretExplanationCatalog {
    static final String VERSION = "secret-explanation-v1";
    private static final Map<String, String> FACTS = Map.ofEntries(
            Map.entry("COLLECTION_SUCCEEDED", "원문 수집을 마쳤어요."),
            Map.entry("COLLECTION_PARTIAL", "원문 일부를 읽지 못했어요."),
            Map.entry("COLLECTION_FAILED", "원문 수집에 실패했어요."),
            Map.entry("COLLECTION_PENDING", "원문 수집을 기다리고 있어요."),
            Map.entry("COLLECTION_RUNNING", "원문을 수집하고 있어요."),
            Map.entry("COLLECTION_SKIPPED", "이번 실행의 원문 수집은 생략됐어요."),
            Map.entry("DETECTION_SUCCEEDED", "읽은 자료의 탐지를 마쳤어요."),
            Map.entry("DETECTION_PARTIAL", "일부 자료의 탐지를 마치지 못했어요."),
            Map.entry("DETECTION_FAILED", "탐지 도구 실행을 마치지 못했어요."),
            Map.entry("DETECTION_PENDING", "탐지를 기다리고 있어요."),
            Map.entry("DETECTION_RUNNING", "키 후보를 탐지하고 있어요."),
            Map.entry("DETECTION_SKIPPED", "이번 실행의 탐지 단계는 생략됐어요."),
            Map.entry("VALIDATION_SUCCEEDED", "인증 확인 단계의 처리를 마쳤어요. 키별 결과를 확인하세요."),
            Map.entry("VALIDATION_PARTIAL", "일부 키의 인증 여부를 확인하지 못했어요."),
            Map.entry("VALIDATION_FAILED", "인증 확인 요청을 마치지 못했어요."),
            Map.entry("VALIDATION_PENDING", "인증 확인을 기다리고 있어요."),
            Map.entry("VALIDATION_RUNNING", "키의 인증 여부를 확인하고 있어요."),
            Map.entry("VALIDATION_SKIPPED", "이번 실행의 인증 확인은 생략됐어요."),
            Map.entry("METADATA_ONLY", "이 실행은 키 존재 정보를 수집해요. 키 원문 인증은 적용 대상이 아니에요."),
            Map.entry("COVERAGE_INCOMPLETE", "전체 범위의 확인이 끝나지 않아 전체 미발견을 확정할 수 없어요."),
            Map.entry("INCOMPLETE_CREDENTIAL", "인증에 필요한 키 구성요소를 함께 확인하지 못했어요."),
            Map.entry("MISSING_SESSION_TOKEN", "AWS 임시 키의 세션 토큰이 없어 인증 여부를 확인하지 못했어요."),
            Map.entry("RATE_LIMITED", "발급 서비스의 호출 제한으로 확인을 마치지 못한 항목이 있어요."),
            Map.entry("SOURCE_UNAVAILABLE", "승인된 원천에서 일부 자료를 다시 읽지 못했어요."),
            Map.entry("VALIDATOR_DISABLED", "이 실행에는 인증 확인 허용 설정이 충족되지 않은 항목이 있어요."),
            Map.entry("RETRY_SCHEDULED", "작업이 다음 자동 재시도를 기다리고 있어요."),
            Map.entry("AUTH_REJECTED", "인증이 거부됐어요. 만료·철회의 구체적 원인은 확정되지 않았어요."),
            Map.entry("AUTH_CONFIRMED", "기록된 시점에 인증 성공이 확인됐어요."),
            Map.entry("AUTH_UNCONFIRMED", "현재 사용할 수 있는 근거로 인증 여부를 확인하지 못했어요."),
            Map.entry("CASE_OPEN", "대응을 시작할 단계예요."),
            Map.entry("CASE_IN_PROGRESS", "조치를 진행하고 있어요."),
            Map.entry("CASE_REVALIDATION_PENDING", "조치 이후의 재검사 결과를 기다리고 있어요."),
            Map.entry("CASE_RESOLVED", "대응 건의 종결 기록이 있어요."),
            Map.entry("ACTION_RECORDED", "조치 기록이 저장돼 있어요."),
            Map.entry("NO_ACTION_RECORD", "아직 저장된 조치 기록이 없어요."),
            Map.entry("UNRESOLVED_LOCATIONS", "확인이 끝나지 않은 대응 위치가 있어요."),
            Map.entry("ASSIGNEE_REQUIRED", "대응 담당자를 지정해야 해요."));
    private static final Map<String, String> ACTIONS = Map.of(
            "VIEW_FINDINGS", "탐지 근거 보기", "VIEW_LOCATIONS", "발견 위치 보기",
            "OPEN_SETTINGS", "연결 설정 확인", "RETRY_FAILED_SCOPES", "재검사 요청으로 이동",
            "CHECK_STATUS", "검사 상태 보기", "OPEN_CASE", "대응 건 확인",
            "ASSIGN_SELF", "담당자 지정 열기", "RECORD_ACTION", "조치 기록 열기",
            "REVALIDATE", "재검사 화면 열기", "REVIEW_CLOSURE", "남은 종결 조건 확인");

    static Set<String> factCodes() { return FACTS.keySet(); }
    static Set<String> actionCodes() { return ACTIONS.keySet(); }
    static String factLabel(String code) { return FACTS.get(code); }
    static String actionLabel(String code) { return ACTIONS.get(code); }

    static Map<String, String> publicFacts() { return FACTS; }
    static Map<String, String> publicActions() { return ACTIONS; }

    static List<SecretExplanationResponse.Document> documents(String issuer) {
        return documents(issuer, "OTHER");
    }

    static List<SecretExplanationResponse.Document> documents(String issuer, String type) {
        if ("AWS".equals(issuer) && "AWS_TEMPORARY_CREDENTIALS".equals(type)) {
            return List.of(new SecretExplanationResponse.Document("AWS_TEMPORARY", "AWS 임시 자격 증명 관리",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp.html", "2026-11-17"));
        }
        return switch (issuer) {
            case "GITHUB" -> List.of(new SecretExplanationResponse.Document("GITHUB_PAT",
                    "GitHub 토큰 관리", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens", "2026-11-17"));
            case "AWS" -> List.of(new SecretExplanationResponse.Document("AWS_ACCESS_KEYS",
                    "AWS 액세스 키 관리", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html", "2026-11-17"));
            case "NOTION" -> List.of(new SecretExplanationResponse.Document("NOTION_AUTH",
                    "Notion 연결 인증", "https://developers.notion.com/guides/authorization/overview", "2026-11-17"));
            default -> List.of();
        };
    }

    static String fallback(SecretExplanationContext context) {
        if (context.facts().contains("METADATA_ONLY")) return factLabel("METADATA_ONLY");
        if (context.facts().contains("CASE_REVALIDATION_PENDING")) {
            return "기록된 조치 이후의 검사 결과를 확인하고 남은 위치와 종결 조건을 검토하세요.";
        }
        return context.facts().stream().limit(3).map(FACTS::get)
                .collect(java.util.stream.Collectors.joining(" "));
    }
}
