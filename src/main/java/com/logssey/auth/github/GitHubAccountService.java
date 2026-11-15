package com.logssey.auth.github;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.logssey.auth.github.GitHubAccountRepository.Account;

/**
 * GitHub로 들어온 사람을 dashboard_users 계정과 잇는다 (ADR-D010).
 *
 * - 계정은 GitHub 계정 ID(github_id)로 찾는다. GitHub 이름이 바뀌면 login_id 도 따라 바꾼다.
 * - 처음 들어온 사람은 ADMIN 계정으로 만든다. login_id 는 GitHub 이름이다.
 * - 같은 login_id 의 비밀번호 계정이 있으면 거부한다. GitHub 이름이 admin 인 사람이 비상용 admin 을 가로채지 못하게.
 *
 * 다른 모듈은 authentication.getName() = login_id 로 사용자를 찾으므로, 여기서 돌려준 login_id 가 로그인 이름이 된다.
 */
@Service
class GitHubAccountService {

    static final String LOGIN_CONFLICT = "login_conflict";

    private static final Logger log = LoggerFactory.getLogger(GitHubAccountService.class);
    private static final int DISPLAY_NAME_MAX = 50;

    private final GitHubAccountRepository repository;

    GitHubAccountService(GitHubAccountRepository repository) {
        this.repository = repository;
    }

    @Transactional
    Account signIn(long githubId, String login, String name) {
        Account known = repository.findByGithubId(githubId).orElse(null);
        if (known != null) {
            if (!known.loginId().equals(login)) {
                requireLoginFree(login, githubId);
                log.info("GitHub login renamed. userId={} from={} to={}", known.userId(), known.loginId(), login);
            }
            repository.recordLogin(known.userId(), login);
            return new Account(known.userId(), login, known.role(), githubId);
        }

        requireLoginFree(login, githubId);
        Account created = repository.create(login, githubId, displayName(name, login));
        log.info("GitHub account created. userId={} login={}", created.userId(), login);
        return created;
    }

    private void requireLoginFree(String login, long githubId) {
        repository.findByLoginId(login).ifPresent(other -> {
            log.warn("GitHub sign-in refused: login_id is used by another account. login={} githubId={}", login, githubId);
            throw new OAuth2AuthenticationException(new OAuth2Error(LOGIN_CONFLICT),
                    "login_id is used by another account");
        });
    }

    private static String displayName(String name, String login) {
        String value = (name == null || name.isBlank()) ? login : name.strip();
        if (value.codePointCount(0, value.length()) <= DISPLAY_NAME_MAX) {
            return value;
        }
        return value.substring(0, value.offsetByCodePoints(0, DISPLAY_NAME_MAX));
    }
}
