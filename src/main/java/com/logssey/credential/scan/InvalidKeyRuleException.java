package com.logssey.credential.scan;

/** 폼 입력으로 규칙을 만들 수 없을 때. 메시지는 화면에 그대로 보여준다 */
public class InvalidKeyRuleException extends IllegalArgumentException {

    public InvalidKeyRuleException(String message) {
        super(message);
    }
}
