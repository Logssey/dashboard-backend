package com.logssey.iac.run;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * 업로드된 plan 이 민감값을 지운 terraform show -json 결과인지 확인한다 (ADR-06, SR-5).
 * sensitive 표시가 있는 자리에 "(sensitive)" 가 아닌 값이 남아 있으면 받지 않는다.
 * 지우는 일은 러너의 policy/scrub-plan.sh 가 하고, 여기서는 빠뜨린 곳이 없는지만 다시 본다.
 */
@Component
public class IacPlanInspector {

    static final int MAX_COMPRESSED_BYTES = 20 * 1024 * 1024;
    static final int MAX_JSON_BYTES = 128 * 1024 * 1024;
    private static final String MASK = "(sensitive)";

    private final JsonMapper mapper = JsonMapper.builder().build();

    /** gzip 을 풀어 plan JSON 을 돌려준다. 형식이 틀리거나 민감값이 남아 있으면 422. */
    public JsonNode inspect(byte[] gzip) {
        JsonNode plan;
        try {
            plan = mapper.readTree(gunzip(gzip));
        } catch (JacksonException | IOException e) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "plan JSON 형식이 아닙니다.");
        }
        if (plan == null || !plan.isObject() || !plan.path("format_version").isString()) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "plan JSON 형식이 아닙니다.");
        }
        if (hasUnmaskedSensitiveValue(plan)) {
            throw new ApiException(ErrorCode.UNPROCESSABLE, "민감값이 남아 있습니다.");
        }
        return plan;
    }

    private static byte[] gunzip(byte[] gzip) throws IOException {
        try (var in = new GZIPInputStream(new ByteArrayInputStream(gzip)); var out = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                if (out.size() + read > MAX_JSON_BYTES) {
                    // 압축 폭탄: 풀린 크기도 제한한다
                    throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE);
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    static boolean hasUnmaskedSensitiveValue(JsonNode plan) {
        for (String section : new String[] {"resource_changes", "resource_drift"}) {
            for (JsonNode change : plan.path(section)) {
                if (changeLeaks(change.path("change"))) return true;
            }
        }
        for (JsonNode change : plan.path("output_changes")) {
            if (changeLeaks(change)) return true;
        }
        if (valuesLeak(plan.path("planned_values")) || valuesLeak(plan.path("prior_state").path("values"))) {
            return true;
        }
        Set<String> sensitiveVariables = new HashSet<>();
        plan.path("configuration").path("root_module").path("variables").properties().forEach(entry -> {
            if (entry.getValue().path("sensitive").asBoolean(false)) sensitiveVariables.add(entry.getKey());
        });
        for (String name : sensitiveVariables) {
            if (leaks(plan.path("variables").path(name).path("value"), true)) return true;
        }
        return false;
    }

    private static boolean changeLeaks(JsonNode change) {
        return leaks(change.path("before"), change.path("before_sensitive"))
                || leaks(change.path("after"), change.path("after_sensitive"));
    }

    private static boolean valuesLeak(JsonNode values) {
        for (JsonNode output : values.path("outputs")) {
            if (output.path("sensitive").asBoolean(false) && leaks(output.path("value"), true)) return true;
        }
        return moduleLeaks(values.path("root_module"));
    }

    private static boolean moduleLeaks(JsonNode module) {
        for (JsonNode resource : module.path("resources")) {
            if (leaks(resource.path("values"), resource.path("sensitive_values"))) return true;
        }
        for (JsonNode child : module.path("child_modules")) {
            if (moduleLeaks(child)) return true;
        }
        return false;
    }

    private static boolean leaks(JsonNode value, boolean sensitive) {
        return sensitive && !value.isMissingNode() && !value.isNull()
                && !(value.isString() && MASK.equals(value.asString()));
    }

    /** 값과 같은 모양의 표시(marker)를 따라 내려가며 true 인 자리에 지워지지 않은 값이 있는지 본다. */
    private static boolean leaks(JsonNode value, JsonNode marker) {
        if (marker.isBoolean()) {
            return leaks(value, marker.asBoolean());
        }
        if (marker.isObject() && value.isObject()) {
            for (var entry : marker.properties()) {
                if (leaks(value.path(entry.getKey()), entry.getValue())) return true;
            }
        } else if (marker.isArray() && value.isArray()) {
            for (int i = 0; i < Math.min(marker.size(), value.size()); i++) {
                if (leaks(value.get(i), marker.get(i))) return true;
            }
        }
        return false;
    }
}
