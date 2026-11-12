package com.logssey.secret.response;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Versioned, server-authored steps. The model may only select their order and optional checks. */
final class SecretGuideCatalog {
    static final String VERSION = "secret-response-guide-v3";
    static final String TITLE = "시크릿 대응 절차 안내";
    static final String NOTICE = "일반적인 대응 안내입니다. 실제 키 변경, 유효성·위험도 판정 및 해결 승인을 대신하지 않습니다.";

    private static final Map<String, SecretGuideResponse.Step> STEPS = steps();
    private static final Set<String> REQUIRED = Set.of("VERIFY_EXPOSURE", "EXTERNAL_ROTATION",
            "RECORD_ACTION", "REVALIDATE");
    private static final List<String> DEFAULT_ORDER = List.of("VERIFY_EXPOSURE", "REVIEW_USAGE",
            "REVIEW_PERMISSIONS", "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE");

    private SecretGuideCatalog() {
    }

    static SecretGuideResponse fallback() {
        return fallback(null);
    }

    static SecretGuideResponse fallback(SecretGuideContext context) {
        return response("DEFAULT", DEFAULT_ORDER, context);
    }

    static Optional<SecretGuideResponse> fromSelectedCodes(List<String> codes) {
        return fromSelectedCodes(codes, null);
    }

    static Optional<SecretGuideResponse> fromSelectedCodes(List<String> codes, SecretGuideContext context) {
        return fromSelectedCodes(codes, context, "GROQ");
    }

    static Optional<SecretGuideResponse> fromSelectedCodes(List<String> codes, SecretGuideContext context, String provider) {
        if (codes == null || codes.size() < REQUIRED.size() || codes.size() > STEPS.size()
                || !STEPS.keySet().containsAll(codes) || !codes.containsAll(REQUIRED)
                || Set.copyOf(codes).size() != codes.size()
                || !"VERIFY_EXPOSURE".equals(codes.getFirst())
                || !"REVALIDATE".equals(codes.getLast())
                || !(codes.indexOf("EXTERNAL_ROTATION") < codes.indexOf("RECORD_ACTION"))) {
            return Optional.empty();
        }
        return Optional.of(response("CLAUDE".equals(provider) ? "CLAUDE" : "GROQ", codes, context));
    }

    static Set<String> stepCodes() {
        return STEPS.keySet();
    }

    private static SecretGuideResponse response(String source, List<String> codes, SecretGuideContext context) {
        String issuer = context == null ? "OTHER" : context.issuer();
        String stage = context == null ? "OPEN" : context.stage();
        String title = switch (issuer) {
            case "AWS" -> "AWS 인증 수단 대응 안내";
            case "GITHUB" -> "GitHub 토큰 대응 안내";
            case "NOTION" -> "Notion 토큰 대응 안내";
            default -> TITLE;
        };
        var wording = new LinkedHashMap<>(STEPS);
        if ("AWS".equals(issuer)) {
            replace(wording, "REVIEW_USAGE", "AWS 사용 이력 확인", "CloudTrail과 연결된 서비스의 사용 이력을 확인하고 담당자가 의심 활동을 검토하세요.");
            replace(wording, "REVIEW_PERMISSIONS", "AWS 권한 범위 확인", "IAM 정책, 역할과 사용처를 확인하고 최소 권한과 임시 자격 증명 사용을 검토하세요.");
            replace(wording, "EXTERNAL_ROTATION", "AWS에서 외부 조치", context != null && "AWS_TEMPORARY_CREDENTIALS".equals(context.credentialType())
                    ? "담당자가 AWS의 세션·역할 정책과 임시 자격 증명의 만료를 확인하고 필요한 세션 차단 및 사용처 갱신을 수행하세요."
                    : "담당자가 AWS IAM에서 액세스 키를 교체·비활성화하고 사용처를 갱신한 뒤 이전 키의 폐기를 확인하세요.");
        } else if ("GITHUB".equals(issuer)) {
            replace(wording, "REVIEW_USAGE", "GitHub 사용 이력 확인", "GitHub의 토큰 사용 기록과 조직 감사 로그를 확인하고 담당자가 의심 활동을 검토하세요.");
            replace(wording, "REVIEW_PERMISSIONS", "GitHub 토큰 권한 확인", "토큰의 저장소 접근 범위, 조직 승인과 만료를 확인하고 필요한 최소 권한을 검토하세요.");
            replace(wording, "EXTERNAL_ROTATION", "GitHub에서 외부 조치", "담당자가 GitHub에서 토큰을 폐기·재발급하고 CI, 배포 환경 등 해당 토큰의 사용처를 갱신하세요.");
        } else if ("NOTION".equals(issuer)) {
            replace(wording, "REVIEW_USAGE", "Notion 사용 이력 확인", "연결의 사용처와 확인 가능한 워크스페이스 감사 기록을 검토하고 담당자가 의심 활동을 확인하세요.");
            replace(wording, "REVIEW_PERMISSIONS", "Notion 연결 권한 확인", "연결의 콘텐츠 읽기·쓰기 기능과 공유된 페이지 범위를 확인하고 필요한 최소 권한을 검토하세요.");
            replace(wording, "EXTERNAL_ROTATION", "Notion에서 외부 조치", "담당자가 Notion 연결 설정에서 토큰을 교체·폐기하고 연결된 수집기와 사용처의 인증 설정을 갱신하세요.");
        }
        if (context != null && "INVALID".equals(context.validationStatus())) {
            replace(wording, "VERIFY_EXPOSURE", "인증 거부 결과와 사용처 확인", "기록된 인증 거부 응답과 검증 시각을 확인하세요. 만료·폐기·교체 여부와 현재 사용 중인 인증 수단을 담당자가 확인하세요.");
            replace(wording, "EXTERNAL_ROTATION", "교체·폐기 상태와 사용처 점검", "이미 교체·폐기한 키인지 확인하고 사용처의 인증 설정을 점검하세요. 원인이 확인되지 않으면 발급 서비스에서 상태를 확인한 후 필요한 조치를 수행하세요.");
        } else if (context != null && List.of("UNKNOWN", "UNCHECKED").contains(context.validationStatus())) {
            replace(wording, "VERIFY_EXPOSURE", "인증 확인 사유와 구성요소 확인", "키별 미검증·확인 불가 사유를 확인하고 필요한 키 구성요소와 현재 승인 범위를 점검하세요. 가능한 경우 최신 인증 확인 결과를 먼저 확보하세요.");
        }
        if ("IN_PROGRESS".equals(stage)) {
            replace(wording, "VERIFY_EXPOSURE", "진행 중 조치 범위 확인", "현재 담당자와 발견 위치를 확인하고 아직 처리되지 않은 사용처와 조치 근거를 검토하세요.");
        } else if ("REVALIDATION_PENDING".equals(stage)) {
            replace(wording, "VERIFY_EXPOSURE", "재검증 대상 확인", "기록된 외부 조치와 승인된 검사 범위를 확인하세요. 재검증 대기는 해결 완료를 의미하지 않습니다.");
            replace(wording, "EXTERNAL_ROTATION", "외부 조치 결과 검토", "이미 기록한 키 교체·폐기와 사용처 갱신 근거를 검토하고 미완료 조치는 담당자가 외부에서 수행하세요.");
            replace(wording, "RECORD_ACTION", "노출 제거·조치 기록 검토", "발견 위치의 키 원문 제거와 안전한 저장 방식 전환이 기록되어 있는지 확인하세요. 수행자·시각·외부 조치 근거를 검토하고 키 원문은 넣지 마세요.");
            replace(wording, "REVALIDATE", "재검증 결과 검토", "승인된 범위의 재검증 결과와 모든 발견 위치를 검토한 후 별도의 해결 요건을 확인하세요.");
        } else if ("RESOLVED".equals(stage)) {
            replace(wording, "VERIFY_EXPOSURE", "해결 근거 확인", "해결 승인 기록과 발견 위치별 최종 결과를 확인하고 새 노출 여부를 검토하세요.");
            replace(wording, "EXTERNAL_ROTATION", "외부 조치 근거 보관", "수행된 키 교체·폐기와 사용처 갱신의 근거를 보관하세요. 이 안내가 새 외부 조치를 실행하지는 않습니다.");
            replace(wording, "RECORD_ACTION", "노출 제거·조치 근거 보관", "발견 위치의 키 원문 제거와 안전한 저장 방식 전환에 대한 기존 근거를 확인·보관하세요. 수행자·시각·외부 조치 기록에 키 원문을 넣지 마세요.");
            replace(wording, "REVALIDATE", "후속 확인", "새 노출이 발견되면 승인된 범위에서 다시 검사하고 별도 대응 절차를 따르세요.");
        }
        return new SecretGuideResponse(VERSION, source, title,
                codes.stream().map(wording::get).toList(), NOTICE,
                new SecretGuideReadiness("UNAVAILABLE", "NOT_REQUESTED", false, false, false, false));
    }

    private static void replace(Map<String, SecretGuideResponse.Step> steps, String code,
                                String title, String description) {
        steps.put(code, new SecretGuideResponse.Step(code, title, description));
    }

    private static Map<String, SecretGuideResponse.Step> steps() {
        var steps = new LinkedHashMap<String, SecretGuideResponse.Step>();
        steps.put("VERIFY_EXPOSURE", new SecretGuideResponse.Step("VERIFY_EXPOSURE", "노출 근거 확인",
                "발견 위치와 수동 노출 판정의 근거를 확인하고 다른 발견 위치도 살펴보세요."));
        steps.put("REVIEW_USAGE", new SecretGuideResponse.Step("REVIEW_USAGE", "사용 이력 확인",
                "발급 서비스의 사용 이력에서 조치가 필요한 흔적이 있는지 확인하세요."));
        steps.put("REVIEW_PERMISSIONS", new SecretGuideResponse.Step("REVIEW_PERMISSIONS", "권한 범위 확인",
                "해당 인증 수단에 연결된 권한과 영향 범위를 확인하고 최소 권한을 검토하세요."));
        steps.put("EXTERNAL_ROTATION", new SecretGuideResponse.Step("EXTERNAL_ROTATION", "외부에서 키 조치",
                "발급 서비스에서 담당자가 키를 교체하거나 폐기하고 필요한 사용처를 갱신하세요."));
        steps.put("RECORD_ACTION", new SecretGuideResponse.Step("RECORD_ACTION", "노출 제거·조치 기록",
                "발견 위치의 키 원문을 제거하고 안전한 저장 방식으로 옮기세요. 발급 서비스의 키 폐기도 별도로 확인하고 수행자·시각·외부 조치 근거를 키 원문 없이 기록하세요."));
        steps.put("REVALIDATE", new SecretGuideResponse.Step("REVALIDATE", "재검증 요청",
                "조치 후 승인된 범위를 다시 검사하고 모든 발견 위치의 결과를 검토하세요."));
        return Map.copyOf(steps);
    }
}
