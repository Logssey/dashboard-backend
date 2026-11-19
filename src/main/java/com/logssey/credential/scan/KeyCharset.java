package com.logssey.credential.scan;

/** 등록 폼의 "문자 종류" 드롭다운. 각 값이 정규식 문자 클래스 하나로 바뀐다 */
public enum KeyCharset {

    HEX_LOWER("16진수 소문자 (0-9, a-f)", "[0-9a-f]"),
    HEX("16진수 대소문자 (0-9, a-f, A-F)", "[0-9a-fA-F]"),
    ALNUM("영문 대소문자 + 숫자", "[A-Za-z0-9]"),
    ALNUM_UPPER("영문 대문자 + 숫자", "[A-Z0-9]"),
    ALNUM_LOWER("영문 소문자 + 숫자", "[a-z0-9]"),
    DIGITS("숫자만", "[0-9]"),
    BASE64URL("영문 + 숫자 + _ -", "[A-Za-z0-9_-]");

    private final String label;
    private final String characterClass;

    KeyCharset(String label, String characterClass) {
        this.label = label;
        this.characterClass = characterClass;
    }

    public String label() {
        return label;
    }

    public String characterClass() {
        return characterClass;
    }
}
