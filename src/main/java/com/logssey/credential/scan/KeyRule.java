package com.logssey.credential.scan;

import java.util.regex.Pattern;

/**
 * 스캐너가 쓰는 "키 형식 규칙" 하나.
 *
 * - 코드 내장 규칙: {@link SecretPattern} (AWS·Notion). 코드에 박혀 있고 바꾸려면 배포가 필요하다
 * - 사용자 규칙: {@link CustomKeyRule}. 화면 폼에서 등록하고 DB(custom_key_patterns)에서 읽는다
 *
 * 스캐너는 둘을 구분하지 않고 이 인터페이스만 보고 검사한다.
 */
public interface KeyRule {

    /** 찾을 정규식. 키 값은 반드시 1번 그룹에 있어야 한다 */
    Pattern pattern();

    /** credentials.issuer 값. 내장 = AWS/NOTION, 사용자 규칙 = CUSTOM */
    String issuer();

    /** 마스킹할 때 앞에서 보여줄 글자 수 */
    int visiblePrefix();

    /** 이 값만으로 인증할 수 있는 비밀값인지 (식별자면 false) */
    boolean isSecret();
}
