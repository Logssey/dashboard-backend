package com.logssey.auth.github;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.logssey.auth.github.dto.response.AuthOptionsResponse;

/** 로그인 화면이 보여 줄 로그인 방법 (로그인 없이 호출). GitHub 로그인이 설정돼 있으면 github=true */
@RestController
class AuthOptionsController {

    private final boolean gitHubEnabled;

    AuthOptionsController(ObjectProvider<ClientRegistrationRepository> registrations) {
        this.gitHubEnabled = GitHubLoginSecurityConfig.isGitHubEnabled(registrations.getIfAvailable());
    }

    @GetMapping(GitHubLoginSecurityConfig.OPTIONS_PATH)
    AuthOptionsResponse options() {
        return new AuthOptionsResponse(gitHubEnabled);
    }
}
