package com.logssey.reach.rule;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** 규칙·취약 함수 데이터는 파일에서 읽고, DB는 권한 확인에만 쓴다 */
@Repository
public class ReachRuleRepository {

    private final JdbcClient jdbcClient;

    public ReachRuleRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    boolean isAdmin(String loginId) {
        return Boolean.TRUE.equals(jdbcClient
                .sql("SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN')")
                .param("loginId", loginId)
                .query(Boolean.class)
                .single());
    }
}
