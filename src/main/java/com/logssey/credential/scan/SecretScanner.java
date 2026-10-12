package com.logssey.credential.scan;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;

/** 글에서 키처럼 생긴 문자열을 찾는다. 같은 값은 한 번만 돌려준다 */
public final class SecretScanner {

    private SecretScanner() {
    }

    public static List<SecretMatch> scan(String text) {
        if (text == null || text.isEmpty()) {
            return List.of();
        }
        Set<SecretMatch> found = new LinkedHashSet<>();
        for (SecretPattern pattern : SecretPattern.values()) {
            Matcher matcher = pattern.pattern().matcher(text);
            while (matcher.find()) {
                found.add(new SecretMatch(pattern, matcher.group(1)));
            }
        }
        return new ArrayList<>(found);
    }
}
