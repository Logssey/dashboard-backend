package com.logssey.credential.scan;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * 폼 입력(접두사 + 문자 종류 + 길이) → 정규식. 사용자는 정규식을 직접 쓰지 않는다.
 *
 * 예: rik_ + HEX_LOWER + 32 → (?<![A-Za-z0-9_-])(\Qrik_\E[0-9a-f]{32})(?![0-9a-f])
 *
 * - 앞 조건 (?<!...): 다른 단어 중간에서 시작한 것은 잡지 않는다 (예: xrik_...)
 * - 뒤 조건 (?!...): 더 긴 문자열의 앞부분만 잘라 잡지 않는다 (예: 33자짜리)
 * - 접두사는 Pattern.quote(\Q...\E)로 감싸서 . 같은 글자가 정규식 문법으로 해석되지 않는다
 * - 만들어지는 정규식은 "고정 문자열 + 문자 클래스{n}" 모양뿐이라 역추적 폭발(ReDoS)이 생기지 않는다
 *
 * 정규식은 DB에 저장하지 않고 스캔할 때마다 여기서 다시 만든다. DB 값이 바뀌어도 이 모양 밖의 정규식은 생길 수 없다.
 */
public final class KeyRuleCompiler {

    public static final int MIN_PREFIX = 2;
    public static final int MAX_PREFIX = 20;
    /** 마스킹이 끝 4자를 보여주므로, 너무 짧으면 노출 비율이 커진다 */
    public static final int MIN_LENGTH = 16;
    public static final int MAX_LENGTH = 128;
    public static final int MAX_NAME = 50;

    /** 접두사에 쓸 수 있는 글자. 공백·따옴표·정규식 특수문자를 막는다 */
    private static final Pattern PREFIX_ALLOWED = Pattern.compile("[A-Za-z0-9_\\-.]+");
    /**
     * 기본 규칙이 이미 잡는 접두사. 같은 키를 두 규칙이 잡지 않도록 막는다 (대소문자 무시, "~로 시작"으로 비교).
     * - 백엔드 SecretPattern: AWS Access Key ID(AKIA·ASIA), Notion 토큰(ntn_)
     * - secret-worker Gitleaks: GitHub 토큰(ghp_·gho_·ghu_·ghs_·ghr_·github_pat_), Notion 옛 토큰(secret_)
     */
    private static final String[] RESERVED_PREFIXES = {
            "AKIA", "ASIA", "ntn_",
            "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
            "secret_"};

    private KeyRuleCompiler() {
    }

    /** 입력을 검사한다. 문제가 있으면 화면에 그대로 보여줄 문장을 담아 예외를 던진다 */
    public static void validate(String name, String prefix, KeyCharset charset, Integer length) {
        if (name == null || name.isBlank()) {
            throw new InvalidKeyRuleException("이름을 입력해 주세요.");
        }
        if (name.strip().length() > MAX_NAME) {
            throw new InvalidKeyRuleException("이름은 %d자 이하로 입력해 주세요.".formatted(MAX_NAME));
        }
        if (prefix == null || prefix.length() < MIN_PREFIX || prefix.length() > MAX_PREFIX) {
            throw new InvalidKeyRuleException(
                    "접두사는 %d~%d자로 입력해 주세요. 접두사가 짧으면 일반 글자를 키로 잘못 잡아요.".formatted(MIN_PREFIX, MAX_PREFIX));
        }
        if (!PREFIX_ALLOWED.matcher(prefix).matches()) {
            throw new InvalidKeyRuleException("접두사에는 영문·숫자와 _ - . 만 쓸 수 있어요.");
        }
        for (String reserved : RESERVED_PREFIXES) {
            if (prefix.toLowerCase(Locale.ROOT).startsWith(reserved.toLowerCase(Locale.ROOT))) {
                throw new InvalidKeyRuleException("'%s'로 시작하는 키는 기본 규칙이 이미 찾고 있어요.".formatted(reserved));
            }
        }
        if (charset == null) {
            throw new InvalidKeyRuleException("문자 종류를 골라 주세요.");
        }
        if (length == null || length < MIN_LENGTH || length > MAX_LENGTH) {
            throw new InvalidKeyRuleException(
                    "길이(접두사 뒤 글자 수)는 %d~%d 사이로 입력해 주세요.".formatted(MIN_LENGTH, MAX_LENGTH));
        }
    }

    /** 실제 검사에 쓰는 정규식 문자열 */
    public static String regex(String prefix, KeyCharset charset, int length) {
        String cls = charset.characterClass();
        return "(?<![A-Za-z0-9_-])(" + Pattern.quote(prefix) + cls + "{" + length + "})(?!" + cls + ")";
    }

    /** 화면에 보여줄 읽기 쉬운 형태. 예: rik_[0-9a-f]{32} */
    public static String readable(String prefix, KeyCharset charset, int length) {
        return prefix + charset.characterClass() + "{" + length + "}";
    }

    /** 검사 + 정규식 생성. DB에서 읽은 값도 반드시 이 경로로 다시 만든다 */
    public static CustomKeyRule build(long id, String name, String prefix, KeyCharset charset, int length, boolean secret) {
        validate(name, prefix, charset, length);
        return new CustomKeyRule(id, name.strip(), prefix, charset, length, secret,
                Pattern.compile(regex(prefix, charset, length)));
    }

    /** 화면 미리보기용 예시 값. 실제 키처럼 보이지 않게 한 글자를 반복한다 */
    public static String example(String prefix, KeyCharset charset, int length) {
        char filler = switch (charset) {
            case HEX_LOWER, ALNUM_LOWER, BASE64URL, ALNUM -> 'a';
            case HEX -> 'A';
            case ALNUM_UPPER -> 'X';
            case DIGITS -> '0';
        };
        return prefix + String.valueOf(filler).repeat(length);
    }
}
