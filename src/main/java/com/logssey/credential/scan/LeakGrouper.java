package com.logssey.credential.scan;

import java.util.ArrayList;
import java.util.List;

/**
 * 한 페이지에서 찾은 문자열을 키 단위로 묶는다.
 *
 * - AWS: Access Key ID와 Secret Access Key를 나온 순서대로 짝짓는다. 짝이 있으면 비밀값이 보인 키(CRITICAL),
 *   ID만 있으면 식별자만 보인 키(HIGH), Secret만 있으면 ID 없이 비밀값이 보인 키(CRITICAL)
 * - Notion 토큰: 하나씩 비밀값이 보인 키
 */
public final class LeakGrouper {

    private LeakGrouper() {
    }

    public static List<LeakedCredential> group(List<SecretMatch> matches, String location, Fingerprinter fingerprinter) {
        List<SecretMatch> ids = byPattern(matches, SecretPattern.AWS_ACCESS_KEY_ID);
        List<SecretMatch> secrets = byPattern(matches, SecretPattern.AWS_SECRET_ACCESS_KEY);
        List<LeakedCredential> result = new ArrayList<>();

        for (int i = 0; i < ids.size(); i++) {
            SecretMatch id = ids.get(i);
            String fingerprint = i < secrets.size() ? fingerprinter.fingerprint(secrets.get(i).value()) : null;
            result.add(new LeakedCredential("AWS", "AWS_ACCESS_KEY", id.value(),
                    "AWS 키 " + id.masked(), id.masked(), fingerprint, location));
        }
        for (int i = ids.size(); i < secrets.size(); i++) {
            SecretMatch secret = secrets.get(i);
            result.add(new LeakedCredential("AWS", "AWS_ACCESS_KEY", null,
                    "AWS Secret Key " + secret.masked(), secret.masked(),
                    fingerprinter.fingerprint(secret.value()), location));
        }
        for (SecretMatch token : byPattern(matches, SecretPattern.NOTION_TOKEN)) {
            result.add(new LeakedCredential("NOTION", "NOTION_TOKEN", null,
                    "Notion 토큰 " + token.masked(), token.masked(),
                    fingerprinter.fingerprint(token.value()), location));
        }
        return result;
    }

    private static List<SecretMatch> byPattern(List<SecretMatch> matches, SecretPattern pattern) {
        return matches.stream().filter(match -> match.pattern() == pattern).toList();
    }
}
