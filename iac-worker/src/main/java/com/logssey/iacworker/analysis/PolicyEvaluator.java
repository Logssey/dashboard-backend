package com.logssey.iacworker.analysis;

import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 1차 판정용 IAM 평가 (ADR-04). 명시적 거부가 허용보다 우선하고, 허용이 없으면 거부.
 * 조건은 보지 않는다: 조건부 거부는 무조건 거부, 조건부 허용은 허용으로 본다 (Cartography 권한 매핑과 같은 규칙).
 * 1등급 결과는 IAM 시뮬레이터로 다시 확인한다.
 */
public final class PolicyEvaluator {

    private PolicyEvaluator() {
    }

    public static boolean allows(Collection<Policy> policies, String action, String resource) {
        boolean allowed = false;
        for (Policy policy : policies) {
            for (PolicyStatement statement : policy.statements()) {
                if (!matches(statement, action, resource)) continue;
                if ("Deny".equalsIgnoreCase(statement.effect())) return false;
                if ("Allow".equalsIgnoreCase(statement.effect())) allowed = true;
            }
        }
        return allowed;
    }

    static boolean matches(PolicyStatement statement, String action, String resource) {
        boolean actionMatches = statement.notActions() != null && !statement.notActions().isEmpty()
                ? !anyMatches(statement.notActions(), action, true)
                : anyMatches(statement.actions(), action, true);
        if (!actionMatches) return false;
        return statement.notResources() != null && !statement.notResources().isEmpty()
                ? !anyMatches(statement.notResources(), resource, false)
                : anyMatches(statement.resources(), resource, false);
    }

    private static boolean anyMatches(List<String> patterns, String value, boolean caseInsensitive) {
        if (patterns == null) return false;
        for (String pattern : patterns) {
            if (wildcard(pattern, caseInsensitive).matcher(value).matches()) return true;
        }
        return false;
    }

    /** IAM 와일드카드: * 는 여러 글자, ? 는 한 글자. 동작 이름은 대소문자를 구분하지 않는다. */
    private static Pattern wildcard(String pattern, boolean caseInsensitive) {
        StringBuilder regex = new StringBuilder();
        for (char c : pattern.toCharArray()) {
            switch (c) {
                case '*' -> regex.append(".*");
                case '?' -> regex.append('.');
                default -> regex.append(Pattern.quote(String.valueOf(c)));
            }
        }
        return Pattern.compile(regex.toString(), caseInsensitive ? Pattern.CASE_INSENSITIVE : 0);
    }
}
