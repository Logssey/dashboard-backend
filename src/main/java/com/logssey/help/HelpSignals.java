package com.logssey.help;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Yes/no environment signals the panel may attach to an incident question (design doc 18.3).
 * Only the fixed keys below are accepted and only real booleans; anything else is dropped. The model sees a
 * sentence the server writes from this fixed table, never text from the request, so no counts, names or
 * attacker-controlled strings can reach it.
 */
final class HelpSignals {

    /** Fixed keys in the order they are written, with the server's own wording. */
    static final Map<String, String> LABELS;
    private static final String[] ORDER;

    static {
        var labels = new LinkedHashMap<String, String>();
        labels.put("runtimeUnreviewed", "검토 안 한 런타임 탐지(의심스러운 시도)");
        labels.put("sensorsDown", "정상인 런타임 센서가 하나도 없음(Logssey로 침해 흔적을 볼 수 없음)");
        labels.put("liveKeys", "살아 있는 키 또는 실키 경고");
        labels.put("keyExposure", "확인이 필요한 키 노출 위치");
        labels.put("openPaths", "바깥에서 닿는 1순위 공격 경로");
        labels.put("severeReachable", "실행 중이면서 도달 가능한 Critical·High 취약점");
        labels.put("drifts", "코드와 다르게 바뀐 설정(드리프트)");
        labels.put("unscanned", "스캔하지 않은 실행 중 워크로드");
        LABELS = Map.copyOf(labels);
        ORDER = labels.keySet().toArray(String[]::new);
    }

    private HelpSignals() {
    }

    /** Keeps only known keys with boolean values, in the fixed order. Null or empty when nothing usable came in. */
    static Map<String, Boolean> clean(Map<String, ?> raw) {
        var cleaned = new LinkedHashMap<String, Boolean>();
        if (raw == null) return cleaned;
        for (String key : ORDER) {
            if (raw.get(key) instanceof Boolean value) cleaned.put(key, value);
        }
        return cleaned;
    }

    /** The server-written block for the model, or an empty string when there are no signals. */
    static String text(Map<String, Boolean> signals) {
        if (signals == null || signals.isEmpty()) return "";
        var text = new StringBuilder("Logssey 환경 신호 (서버가 예/아니오로만 알려 줌, 숫자와 이름은 없음):\n");
        for (String key : ORDER) {
            Boolean value = signals.get(key);
            if (value != null) text.append("- ").append(LABELS.get(key)).append(": ").append(value ? "있음" : "없음").append('\n');
        }
        return text.append('\n').toString();
    }
}
