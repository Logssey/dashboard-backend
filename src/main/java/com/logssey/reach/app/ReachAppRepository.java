package com.logssey.reach.app;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** 앱 목록은 설정에서 읽고, DB는 권한 확인에만 쓴다 */
@Repository
public class ReachAppRepository {

    private final JdbcClient jdbcClient;

    public ReachAppRepository(JdbcClient jdbcClient) {
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
