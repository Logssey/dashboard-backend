package com.logssey.credential.scan;

/** 글에서 찾은 키 한 개. value는 원문이므로 저장하거나 로그에 남기지 않는다 */
public record SecretMatch(KeyRule pattern, String value) {

    /** 화면·DB에 쓸 마스킹 값. 예: AKIA****MPLE, ntn_****abcd, ****EKEY */
    public String masked() {
        String prefix = value.substring(0, Math.min(pattern.visiblePrefix(), value.length()));
        String suffix = value.length() > 8 ? value.substring(value.length() - 4) : "";
        return prefix + "****" + suffix;
    }

    @Override
    public String toString() {
        return "SecretMatch[pattern=" + pattern + ", value=" + masked() + "]";
    }
}
