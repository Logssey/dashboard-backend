package com.logssey.auth;

import java.time.Instant;

import com.logssey.auth.dto.response.LoginResponse;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.user.DashboardUser;
import com.logssey.user.DashboardUserRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final DashboardUserRepository userRepository;

    public AuthService(DashboardUserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /** 로그인 성공 후 마지막 로그인 시각을 기록한다 */
    @Transactional
    public LoginResponse recordLogin(String loginId) {
        DashboardUser user = findUser(loginId);
        user.recordLogin(Instant.now());
        return LoginResponse.from(user);
    }

    @Transactional(readOnly = true)
    public LoginResponse getMe(String loginId) {
        return LoginResponse.from(findUser(loginId));
    }

    private DashboardUser findUser(String loginId) {
        return userRepository.findByLoginId(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
    }
}
