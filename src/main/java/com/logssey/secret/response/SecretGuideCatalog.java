package com.logssey.secret.response;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Versioned, server-authored steps. The model may only select their order and optional checks. */
final class SecretGuideCatalog {
    static final String VERSION = "secret-response-guide-v1";
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
        return response("DEFAULT", DEFAULT_ORDER);
    }

    static Optional<SecretGuideResponse> fromSelectedCodes(List<String> codes) {
        if (codes == null || codes.size() < REQUIRED.size() || codes.size() > STEPS.size()
                || !STEPS.keySet().containsAll(codes) || !codes.containsAll(REQUIRED)
                || Set.copyOf(codes).size() != codes.size()
                || !"VERIFY_EXPOSURE".equals(codes.getFirst())
                || !"REVALIDATE".equals(codes.getLast())
                || !(codes.indexOf("EXTERNAL_ROTATION") < codes.indexOf("RECORD_ACTION"))) {
            return Optional.empty();
        }
        return Optional.of(response("GROQ", codes));
    }

    static Set<String> stepCodes() {
        return STEPS.keySet();
    }

    private static SecretGuideResponse response(String source, List<String> codes) {
        return new SecretGuideResponse(VERSION, source, TITLE,
                codes.stream().map(STEPS::get).toList(), NOTICE);
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
        steps.put("RECORD_ACTION", new SecretGuideResponse.Step("RECORD_ACTION", "조치 근거 기록",
                "수행자, 시각, 대상 위치와 외부 조치 근거를 대응 건에 기록하세요. 키 원문은 넣지 마세요."));
        steps.put("REVALIDATE", new SecretGuideResponse.Step("REVALIDATE", "재검증 요청",
                "조치 후 승인된 범위를 다시 검사하고 모든 발견 위치의 결과를 검토하세요."));
        return Map.copyOf(steps);
    }
}
