package com.logssey.credential.event;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import com.logssey.credential.risk.TokenRiskEvaluator;
import com.logssey.credential.risk.TokenRiskFinding;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * 저장된 키를 위험 판단 코드에 넣고, 찾은 위험을 탐지 이벤트로 등록한다.
 *
 * - 기준값은 06-test/notion-admin-mock-scenarios.md 1장 (TokenRiskEvaluator)
 * - 같은 키 + 같은 제목의 탐지가 이미 있으면 다시 만들지 않는다
 * - 발생 시각은 판단한 시각이다
 * - 화면 ID는 SEC- + 지금까지 쓴 가장 큰 번호 다음 번호 (ERD 화면 ID 검토 방향)
 */
@Service
public class CredentialRiskEventService {

    private static final Logger log = LoggerFactory.getLogger(CredentialRiskEventService.class);

    private final CredentialRiskRepository repository;
    private final Clock clock;

    @Autowired
    public CredentialRiskEventService(CredentialRiskRepository repository) {
        this(repository, Clock.systemUTC());
    }

    CredentialRiskEventService(CredentialRiskRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    /** @return 새로 만든 탐지 이벤트 수 */
    @Transactional
    public int createRiskEvents() {
        Instant now = clock.instant();
        TokenRiskEvaluator evaluator = new TokenRiskEvaluator(clock);
        Set<CredentialRiskRepository.EventKey> existing = repository.findExistingEventKeys();
        int nextNumber = repository.findMaxSecretsNumber() + 1;
        int created = 0;

        List<StoredCredential> credentials = repository.findAllCredentials();
        for (StoredCredential stored : credentials) {
            for (TokenRiskFinding finding : evaluator.evaluate(stored.credential())) {
                String title = CredentialRiskEventFactory.title(stored.credential().issuer(), finding.type());
                CredentialRiskRepository.EventKey key =
                        new CredentialRiskRepository.EventKey(stored.credentialId(), title);
                if (existing.contains(key)) {
                    continue;
                }
                String displayId = "SEC-%03d".formatted(nextNumber++);
                repository.insertEvent(CredentialRiskEventFactory.create(stored, finding, now, displayId));
                existing.add(key);
                created++;
            }
        }
        log.info("Credential risk check finished. credentials={}, newEvents={}", credentials.size(), created);
        return created;
    }
}
