package com.logssey.iacworker.analysis;

import java.util.List;

/** 역할에 붙은 정책 하나. key 는 inline:<이름> 또는 managed:<ARN>. */
public record Policy(String key, String id, List<PolicyStatement> statements) {

    static String inlineKey(String name) {
        return "inline:" + name;
    }

    static String managedKey(String arn) {
        return "managed:" + arn;
    }
}
