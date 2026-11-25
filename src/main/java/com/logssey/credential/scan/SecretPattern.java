package com.logssey.credential.scan;

import java.util.regex.Pattern;

/**
 * 페이지에서 찾는 키 형식 중 코드에 내장된 것 (사용자 등록 형식은 CustomKeyRule, DB에서 읽음).
 *
 * - AWS Access Key ID: AKIA(장기 키)·ASIA(임시 키) + 대문자·숫자 16자. 식별자라 혼자서는 접속할 수 없다
 * - AWS Secret Access Key: 40자. 형식만으로는 일반 글자와 구분되지 않아 "aws_secret_access_key =" 같은 이름이 앞에 있을 때만 찾는다
 * - Notion 토큰: ntn_ + 영문·숫자. 실제 발급 토큰에서 형식을 확인했다 (ntn_ + 46자)
 */
public enum SecretPattern implements KeyRule {

    AWS_ACCESS_KEY_ID(
            Pattern.compile("\\b((?:AKIA|ASIA)[0-9A-Z]{16})\\b"), "AWS", 4, false),
    AWS_SECRET_ACCESS_KEY(
            Pattern.compile("(?i)aws_?secret_?access_?key[\"']?\\s*[:=]\\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
            "AWS", 0, true),
    NOTION_TOKEN(
            Pattern.compile("\\b(ntn_[A-Za-z0-9]{40,})\\b"), "NOTION", 4, true);

    private final Pattern pattern;
    private final String issuer;
    private final int visiblePrefix;
    private final boolean secret;

    SecretPattern(Pattern pattern, String issuer, int visiblePrefix, boolean secret) {
        this.pattern = pattern;
        this.issuer = issuer;
        this.visiblePrefix = visiblePrefix;
        this.secret = secret;
    }

    @Override
    public Pattern pattern() {
        return pattern;
    }

    @Override
    public String issuer() {
        return issuer;
    }

    /** 마스킹할 때 앞에서 보여줄 글자 수. 비밀값 본문은 앞을 보여주지 않는다 */
    @Override
    public int visiblePrefix() {
        return visiblePrefix;
    }

    /** 이 값만으로 인증할 수 있는 비밀값인지 (Access Key ID는 식별자라 false) */
    @Override
    public boolean isSecret() {
        return secret;
    }
}
