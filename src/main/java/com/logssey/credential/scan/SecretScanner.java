package com.logssey.credential.scan;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

/**
 * 글에서 키처럼 생긴 문자열을 찾는다. 같은 값은 한 번만 돌려준다.
 *
 * 검사 규칙 = 코드 내장 규칙(SecretPattern) + 사용자가 등록한 규칙(CustomKeyRule, DB).
 * 같은 값을 내장 규칙과 사용자 규칙이 모두 잡으면 내장 규칙 결과만 남긴다.
 */
public final class SecretScanner {

    private SecretScanner() {
    }

    /** 내장 규칙만으로 검사 */
    public static List<SecretMatch> scan(String text) {
        return scan(text, List.of());
    }

    /** 내장 규칙 + 사용자 규칙으로 검사 */
    public static List<SecretMatch> scan(String text, List<? extends KeyRule> customRules) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        Set<SecretMatch> found = new LinkedHashSet<>();
        Set<String> builtInValues = new HashSet<>();
        for (SecretPattern pattern : SecretPattern.values()) {
            Matcher matcher = pattern.pattern().matcher(text);
            while (matcher.find()) {
                found.add(new SecretMatch(pattern, matcher.group(1)));
                builtInValues.add(matcher.group(1));
            }
        }
        for (KeyRule rule : customRules) {
            Matcher matcher = rule.pattern().matcher(text);
            while (matcher.find()) {
                if (!builtInValues.contains(matcher.group(1))) {
                    found.add(new SecretMatch(rule, matcher.group(1)));
                }
            }
        }
        return new ArrayList<>(found);
    }
}
