package com.logssey.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * 서버가 켜질 때 .env의 관리자 계정을 등록한다 (ADR-D003).
 *
 * - 계정이 없으면 만든다. 비밀번호는 BCrypt 해시로 저장한다.
 * - 계정이 이미 있으면 그대로 둔다. .env의 비밀번호를 바꿔도 기존 비밀번호는 바뀌지 않는다.
 * - 비밀번호는 로그에 절대 남기지 않는다.
 */
@Component
public class AdminAccountInitializer implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminAccountInitializer.class);

    private final DashboardUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final String loginId;
    private final String password;
    private final String displayName;

    public AdminAccountInitializer(DashboardUserRepository userRepository,
                                   PasswordEncoder passwordEncoder,
                                   @Value("${logssey.admin.login-id}") String loginId,
                                   @Value("${logssey.admin.password}") String password,
                                   @Value("${logssey.admin.display-name}") String displayName) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.loginId = loginId;
        this.password = password;
        this.displayName = displayName;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        requireNotBlank(loginId, "ADMIN_LOGIN_ID");
        requireNotBlank(password, "ADMIN_PASSWORD");
        requireNotBlank(displayName, "ADMIN_DISPLAY_NAME");

        if (userRepository.existsByLoginId(loginId)) {
            log.info("Admin account already exists. Keeping the current password. loginId={}", loginId);
            return;
        }

        userRepository.save(DashboardUser.createAdmin(loginId, passwordEncoder.encode(password), displayName));
        log.info("Admin account created. loginId={}", loginId);
    }

    private static void requireNotBlank(String value, String envName) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(envName + " is empty. Set it in the .env file.");
        }
    }
}
