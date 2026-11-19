package com.logssey.credential.scan;

import java.util.regex.Pattern;

/**
 * 사용자가 화면 폼으로 등록한 키 형식 (custom_key_patterns 한 줄).
 * 정규식은 사람이 쓰지 않는다. {@link KeyRuleCompiler}가 접두사·문자 종류·길이로 만든다.
 *
 * @param id      custom_key_patterns.pattern_id
 * @param name    화면에 보일 이름. 예: 사내 RIK 키
 * @param prefix  접두사. 예: rik_
 * @param charset 접두사 뒤 문자 종류
 * @param length  접두사 뒤 글자 수
 * @param secret  비밀값이면 true (지문만 저장), 식별자면 false
 * @param pattern KeyRuleCompiler가 만든 정규식
 */
public record CustomKeyRule(
        long id,
        String name,
        String prefix,
        KeyCharset charset,
        int length,
        boolean secret,
        Pattern pattern) implements KeyRule {

    public static final String ISSUER = "CUSTOM";
    public static final String CREDENTIAL_TYPE = "CUSTOM_KEY";

    @Override
    public String issuer() {
        return ISSUER;
    }

    /** 접두사는 공개 정보라 그대로 보여준다. 예: rik_****9f3a */
    @Override
    public int visiblePrefix() {
        return prefix.length();
    }

    @Override
    public boolean isSecret() {
        return secret;
    }
}
