package com.logssey.secret.response;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretCaseServiceTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private SecretCaseService service;
    private long securityUser;
    private long remediatorUser;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE secret_connections, dashboard_users RESTART IDENTITY CASCADE");
        securityUser = user("security", "Security");
        remediatorUser = user("remediator", "Remediator");
        service = new SecretCaseService(new SecretCaseRepository(jdbc));
    }

    @Test
    void migrationDoesNotInventCasesFromUnknownFindingsOrMetadata() {
        long connection = connection("GITHUB");
        long scope = scope(connection);
        long confirmed = credential("CONFIRMED", "AWS ••••1234");
        long metadata = credential("METADATA_ONLY", "AWS IAM ••••5678");
        occurrence(confirmed, connection, scope, "UNKNOWN");
        occurrence(metadata, connection, scope, "UNKNOWN");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_response_cases", Long.class))
                .isZero();
        assertCode(ErrorCode.FORBIDDEN, () -> service.list(0, 20, "PRODUCTION", "security"));
    }

    @Test
    void explicitOpeningRequiresEvidenceAndUsesApprovedScopeOrigin() {
        long connection = connection("GITHUB");
        long scope = scope(connection);
        long secret = credential("CONFIRMED", "AWS ••••1234");
        long occurrence = occurrence(secret, connection, scope, "ABNORMAL");
        grant(securityUser, "SECURITY", connection);
        var request = openRequest(occurrence);

        assertCode(ErrorCode.CONFLICT, () -> service.open(secret, request, "security"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_response_cases", Long.class)).isZero();
        classifyScope(scope, "TEST");
        var opened = service.open(secret, request, "security");
        assertThat(opened.caseOrigin()).isEqualTo("TEST");
        assertThat(opened.openingOccurrenceId()).isEqualTo(occurrence);
        assertThat(opened.openingReason()).isEqualTo("ASSESSED_EXPOSURE");
        assertThat(service.list(0, 20, "PRODUCTION", "security").total()).isZero();
        assertThat(service.list(0, 20, "TEST", "security").total()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events WHERE event_type = 'CASE_OPENED'", Long.class))
                .isEqualTo(1);
        assertCode(ErrorCode.CONFLICT, () -> service.open(secret, request, "security"));

        long productionConnection = connection("GITHUB");
        long productionScope = scope(productionConnection);
        classifyScope(productionScope, "PRODUCTION");
        grant(securityUser, "SECURITY", productionConnection);
        long productionOccurrence = occurrence(secret, productionConnection, productionScope, "ABNORMAL");
        var productionCase = service.open(secret,
                openRequest(productionOccurrence), "security");
        assertThat(productionCase.caseOrigin()).isEqualTo("PRODUCTION");
        assertThat(service.list(0, 20, "PRODUCTION", "security").total()).isEqualTo(1);
        assertThat(service.list(0, 20, "TEST", "security").total()).isEqualTo(1);
    }

    @Test
    void incompleteMetadataUnknownAndNormalStorageCannotOpenCase() {
        long github = connection("GITHUB");
        long githubScope = scope(github);
        classifyScope(githubScope, "TEST");
        grant(securityUser, "SECURITY", github);
        long confirmed = credential("CONFIRMED", "AWS ••••1234");
        long unknown = occurrence(confirmed, github, githubScope, "UNKNOWN");
        assertCode(ErrorCode.CONFLICT, () -> service.open(confirmed,
                openRequest(unknown), "security"));
        long metadata = credential("METADATA_ONLY", "AWS IAM ••••5678");
        long metadataOccurrence = occurrence(metadata, github, githubScope, "ABNORMAL");
        assertCode(ErrorCode.CONFLICT, () -> service.open(metadata,
                openRequest(metadataOccurrence), "security"));
        long candidate = credential("CANDIDATE", "AWS ••••9012");
        long candidateOccurrence = occurrence(candidate, github, githubScope, "ABNORMAL");
        assertCode(ErrorCode.CONFLICT, () -> service.open(candidate,
                openRequest(candidateOccurrence), "security"));

        long aws = connection("AWS");
        long awsScope = scope(aws);
        classifyScope(awsScope, "PRODUCTION");
        grant(securityUser, "SECURITY", aws);
        long stored = credential("CONFIRMED", "AWS ••••3456");
        long storedOccurrence = occurrence(stored, aws, awsScope, "ABNORMAL");
        assertCode(ErrorCode.CONFLICT, () -> service.open(stored,
                openRequest(storedOccurrence), "security"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_response_cases", Long.class)).isZero();
    }

    @Test
    void assignmentRecordsActorBeforeAfterVersionAndAuditWithoutDuplicatingCurrentCase() {
        long caseId = caseFixture();
        grant(securityUser, "SECURITY", null);
        grant(remediatorUser, "REMEDIATOR", null);
        membership(remediatorUser, "Platform");

        assertThat(service.list(0, 20, "PRODUCTION", "security").items()).singleElement()
                .satisfies(item -> {
                    assertThat(item.caseId()).isEqualTo(caseId);
                    assertThat(item.stage()).isEqualTo("OPEN");
                    assertThat(item.maskedLabel()).isEqualTo("AWS ••••1234");
                });
        assertThat(service.assignees(caseId, "security").items())
                .containsExactly(new SecretAssignee(remediatorUser, "Remediator", "Platform"));

        var updated = service.assign(caseId,
                new SecretAssignmentRequest("Platform", remediatorUser, "INITIAL_ASSIGNMENT", 0L),
                "security");
        assertThat(updated.version()).isEqualTo(1);
        assertThat(updated.stage()).isEqualTo("OPEN");
        assertThat(updated.assigneeUserId()).isEqualTo(remediatorUser);
        assertThat(updated.assigneeDisplayName()).isEqualTo("Remediator");
        assertThat(updated.assignmentHistory()).singleElement().satisfies(history -> {
            assertThat(history.changedByUserId()).isEqualTo(securityUser);
            assertThat(history.changedByDisplayName()).isEqualTo("Security");
            assertThat(history.previousUserId()).isNull();
            assertThat(history.newUserId()).isEqualTo(remediatorUser);
            assertThat(history.newAssigneeDisplayName()).isEqualTo("Remediator");
            assertThat(history.reason()).isEqualTo("INITIAL_ASSIGNMENT");
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_assignment_history", Long.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events WHERE event_type = 'ASSIGNMENT_CHANGED'", Long.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_response_cases WHERE is_current", Long.class))
                .isEqualTo(1);

        assertCode(ErrorCode.CONFLICT, () -> service.assign(caseId,
                new SecretAssignmentRequest(null, null, "UNASSIGNED", 0L), "security"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_assignment_history", Long.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT version FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId)).isEqualTo(1);
    }

    @Test
    void scopedRolesMustCoverEveryLinkedLocationAndAssignmentTargetMustBeEligible() {
        long caseId = caseFixture();
        long secondConnection = connection("GITHUB");
        long secondScope = scope(secondConnection);
        long secretId = jdbc.queryForObject("SELECT credential_set_id FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId);
        long secondOccurrence = occurrence(secretId, secondConnection, secondScope, "ABNORMAL");
        jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, secondOccurrence, secretId);
        long firstConnection = jdbc.queryForObject("""
                SELECT o.connection_id FROM secret_response_cases c
                JOIN secret_occurrences o ON o.occurrence_id = c.opening_occurrence_id
                WHERE c.case_id = ?
                """, Long.class, caseId);
        grant(securityUser, "SECURITY", firstConnection);
        grant(remediatorUser, "REMEDIATOR", firstConnection);
        assertThat(service.list(0, 20, "PRODUCTION", "security").items()).isEmpty();
        assertCode(ErrorCode.FORBIDDEN, () -> service.detail(caseId, "security"));
        grant(securityUser, "SECURITY", secondConnection);
        assertThat(service.detail(caseId, "security").caseId()).isEqualTo(caseId);
        assertThat(service.assignees(caseId, "security").items()).isEmpty();
        assertCode(ErrorCode.INVALID_INPUT, () -> service.assign(caseId,
                new SecretAssignmentRequest(null, remediatorUser, "INITIAL_ASSIGNMENT", 0L),
                "security"));
        grant(remediatorUser, "REMEDIATOR", secondConnection);
        assertThat(service.assignees(caseId, "security").items()).hasSize(1);
    }

    @Test
    void rejectsUnsafeReasonAndTeamWhileSupportingTeamOnlyAndUnassign() {
        long caseId = caseFixture();
        grant(securityUser, "SECURITY", null);
        grant(remediatorUser, "REMEDIATOR", null);
        membership(remediatorUser, "Platform");
        assertCode(ErrorCode.INVALID_INPUT, () -> service.assign(caseId,
                new SecretAssignmentRequest("Platform", remediatorUser, "raw-value-goes-here", 0L),
                "security"));
        assertCode(ErrorCode.INVALID_INPUT, () -> service.assign(caseId,
                new SecretAssignmentRequest("Unknown", null, "INITIAL_ASSIGNMENT", 0L),
                "security"));
        assertThat(service.assign(caseId,
                new SecretAssignmentRequest("Platform", null, "INITIAL_ASSIGNMENT", 0L),
                "security").assigneeTeam()).isEqualTo("Platform");
        assertThat(service.assign(caseId,
                new SecretAssignmentRequest(null, null, "UNASSIGNED", 1L),
                "security").assigneeTeam()).isNull();
    }

    @Test
    void databaseRejectsSecondCurrentCaseAndCrossCredentialOccurrence() {
        long caseId = caseFixture();
        long originalSecret = jdbc.queryForObject("SELECT credential_set_id FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId);
        long anotherSecret = credential("CONFIRMED", "GITHUB ••••5678");
        long connection = connection("GITHUB");
        long anotherOccurrence = occurrence(anotherSecret, connection, scope(connection), "ABNORMAL");
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id, opening_reason, case_origin)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'PRODUCTION')
                """, originalSecret, anotherOccurrence, securityUser))
                .isInstanceOf(DataIntegrityViolationException.class);
        long openingOccurrence = jdbc.queryForObject(
                "SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId);
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id, opening_reason, case_origin)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'PRODUCTION')
                """, originalSecret, openingOccurrence, securityUser))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, anotherOccurrence, originalSecret))
                .isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void reviewChecklistAndExternalActionKeepIndependentEvidenceAndState() {
        long caseId = caseFixture();
        grant(securityUser, "SECURITY", null);
        grant(remediatorUser, "REMEDIATOR", null);
        service.assign(caseId,
                new SecretAssignmentRequest(null, remediatorUser, "INITIAL_ASSIGNMENT", 0L),
                "security");

        var needsInfo = service.review(caseId,
                new SecretCaseReviewRequest("NEEDS_MORE_INFO", "INSUFFICIENT_EVIDENCE", 1L),
                "security");
        assertThat(needsInfo.reviewStatus()).isEqualTo("UNREVIEWED");
        assertThat(needsInfo.stage()).isEqualTo("OPEN");
        assertCode(ErrorCode.CONFLICT, () -> service.start(caseId,
                new SecretCaseStartRequest("RESPONSE_STARTED", 2L), "remediator"));

        var confirmed = service.review(caseId,
                new SecretCaseReviewRequest("CONFIRMED", "EVIDENCE_CONFIRMED", 2L),
                "security");
        assertThat(confirmed.reviewStatus()).isEqualTo("REVIEWED");
        assertThat(confirmed.stage()).isEqualTo("OPEN");
        assertThat(confirmed.reviews()).hasSize(2);
        assertThat(confirmed.capabilities().canStart()).isFalse();
        assertThat(service.detail(caseId, "remediator").capabilities().canStart()).isTrue();

        var started = service.start(caseId,
                new SecretCaseStartRequest("RESPONSE_STARTED", 3L), "remediator");
        assertThat(started.stage()).isEqualTo("IN_PROGRESS");
        assertThat(started.occurrences()).singleElement()
                .extracting(SecretCaseOccurrence::responseStatus).isEqualTo("IN_PROGRESS");
        long itemId = started.checklist().getFirst().itemId();
        var checked = service.checklist(caseId, itemId,
                new SecretChecklistRequest(true, "S2_V1", "TICKET:SEC-123", 4L),
                "remediator");
        assertThat(checked.stage()).isEqualTo("IN_PROGRESS");
        assertThat(checked.checklist().getFirst().status()).isEqualTo("DONE");
        assertThat(checked.checklist().getFirst().evidenceRef()).isEqualTo("TICKET:SEC-123");
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_checklist_history", Long.class))
                .isEqualTo(1);

        var action = service.action(caseId, new SecretActionRequest("ROTATED",
                checked.openingOccurrenceId(), OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(1),
                "CHANGE:SEC-234", 5L), "remediator");
        assertThat(action.stage()).isEqualTo("REVALIDATION_PENDING");
        assertThat(action.occurrences()).singleElement()
                .extracting(SecretCaseOccurrence::responseStatus)
                .isEqualTo("REVALIDATION_PENDING");
        assertThat(action.actions()).singleElement().satisfies(record -> {
            assertThat(record.actionType()).isEqualTo("ROTATED");
            assertThat(record.evidenceRef()).isEqualTo("CHANGE:SEC-234");
            assertThat(record.recordedByUserId()).isEqualTo(remediatorUser);
        });
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events WHERE case_id = ?",
                Long.class, caseId)).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_case_stage_history WHERE case_id = ?",
                Long.class, caseId)).isEqualTo(2);
        assertThat(action.stage()).isNotEqualTo("RESOLVED");
    }

    @Test
    void mutationsRequireCaseWideRoleAssigneeVersionAndControlledInputs() {
        long caseId = caseFixture();
        grant(securityUser, "SECURITY", null);
        grant(remediatorUser, "REMEDIATOR", null);
        long itemId = jdbc.queryForObject(
                "SELECT item_id FROM secret_checklist_items WHERE case_id = ? ORDER BY item_id LIMIT 1",
                Long.class, caseId);
        assertCode(ErrorCode.FORBIDDEN, () -> service.checklist(caseId, itemId,
                new SecretChecklistRequest(true, "S2_V1", "TICKET:SEC-123", 0L),
                "remediator"));
        service.assign(caseId,
                new SecretAssignmentRequest(null, remediatorUser, "INITIAL_ASSIGNMENT", 0L),
                "security");
        assertCode(ErrorCode.INVALID_INPUT, () -> service.review(caseId,
                new SecretCaseReviewRequest("CONFIRMED", "free-form reason", 1L), "security"));
        assertCode(ErrorCode.INVALID_INPUT, () -> service.checklist(caseId, itemId,
                new SecretChecklistRequest(true, "S2_V1", "https://example.test/key", 1L),
                "remediator"));
        assertCode(ErrorCode.CONFLICT, () -> service.checklist(caseId, itemId,
                new SecretChecklistRequest(true, "S2_V1", "TICKET:SEC-123", 0L),
                "remediator"));
        assertCode(ErrorCode.CONFLICT, () -> service.action(caseId, new SecretActionRequest(
                "ROTATED", jdbc.queryForObject("SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id = ?",
                        Long.class, caseId), OffsetDateTime.now(ZoneOffset.UTC),
                "TICKET:SEC-123", 1L), "remediator"));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_checklist_history", Long.class))
                .isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_action_records", Long.class))
                .isZero();
    }

    @Test
    void separateLocationsNeedSeparateActionRecordsBeforeWholeCaseIsPending() {
        long caseId = caseFixture();
        long firstOccurrence = jdbc.queryForObject(
                "SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId);
        long secretId = jdbc.queryForObject(
                "SELECT credential_set_id FROM secret_response_cases WHERE case_id = ?",
                Long.class, caseId);
        long connectionId = jdbc.queryForObject(
                "SELECT connection_id FROM secret_occurrences WHERE occurrence_id = ?",
                Long.class, firstOccurrence);
        long scopeId = jdbc.queryForObject(
                "SELECT scope_id FROM secret_occurrences WHERE occurrence_id = ?",
                Long.class, firstOccurrence);
        long secondOccurrence = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, 'repo/other.txt', 'L2', 'UNKNOWN', 'ABNORMAL', 'UNKNOWN',
                        'PRESENT', now(), now()) RETURNING occurrence_id
                """, Long.class, secretId, connectionId, scopeId);
        jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, secondOccurrence, secretId);
        grant(securityUser, "SECURITY", null);
        grant(remediatorUser, "REMEDIATOR", null);
        service.assign(caseId,
                new SecretAssignmentRequest(null, remediatorUser, "INITIAL_ASSIGNMENT", 0L),
                "security");
        service.review(caseId,
                new SecretCaseReviewRequest("CONFIRMED", "EVIDENCE_CONFIRMED", 1L),
                "security");
        var first = service.action(caseId,
                new SecretActionRequest("REMOVED_FROM_SOURCE", firstOccurrence,
                        OffsetDateTime.now(ZoneOffset.UTC), "TICKET:SEC-123", 2L),
                "remediator");
        assertThat(first.stage()).isEqualTo("IN_PROGRESS");
        assertThat(first.occurrences()).extracting(SecretCaseOccurrence::responseStatus)
                .containsExactly("REVALIDATION_PENDING", "OPEN");
        assertCode(ErrorCode.CONFLICT, () -> service.action(caseId,
                new SecretActionRequest("ROTATED", firstOccurrence,
                        OffsetDateTime.now(ZoneOffset.UTC), "CHANGE:SEC-234", 3L),
                "remediator"));
        var second = service.action(caseId,
                new SecretActionRequest("ROTATED", secondOccurrence,
                        OffsetDateTime.now(ZoneOffset.UTC), "CHANGE:SEC-234", 3L),
                "remediator");
        assertThat(second.stage()).isEqualTo("REVALIDATION_PENDING");
        assertThat(second.actions()).hasSize(2);
    }

    private long caseFixture() {
        long connection = connection("GITHUB");
        long scope = scope(connection);
        long secretId = credential("CONFIRMED", "AWS ••••1234");
        long occurrence = occurrence(secretId, connection, scope, "ABNORMAL");
        long caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id, opening_reason, case_origin)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'PRODUCTION') RETURNING case_id
                """, Long.class, secretId, occurrence, securityUser);
        jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, occurrence, secretId);
        jdbc.update("""
                INSERT INTO secret_checklist_items (case_id, guide_version, item_code)
                VALUES (?, 'S2_V1', 'IDENTIFY_OWNER'),
                       (?, 'S2_V1', 'ROTATE_OR_REVOKE'),
                       (?, 'S2_V1', 'REMOVE_EXPOSURE'),
                       (?, 'S2_V1', 'CHECK_ACCESS_LOGS')
                """, caseId, caseId, caseId, caseId);
        return caseId;
    }

    private long user(String login, String display) {
        return jdbc.queryForObject("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES (?, 'test-hash', ?, 'ADMIN') RETURNING user_id
                """, Long.class, login, display);
    }

    private long connection(String provider) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES (?, 'Test', 'test-ref', 'ACTIVE', 1) RETURNING connection_id
                """, Long.class, provider);
    }

    private long scope(long connectionId) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'fixture', 1, 'GITHUB_REPOSITORY_FILES',
                        'github://Other/fixture/main/src/', 'CURRENT_COMMIT_ONLY', TRUE)
                RETURNING scope_id
                """, Long.class, connectionId);
    }

    private long credential(String state, String label) {
        if ("METADATA_ONLY".equals(state)) {
            return jdbc.queryForObject("""
                    INSERT INTO secret_credential_sets
                        (issuer, credential_type, component_state, masked_label, first_seen_at, last_seen_at)
                    VALUES ('AWS', 'AWS_IAM_ACCESS_KEY', 'METADATA_ONLY', ?, now(), now())
                    RETURNING credential_set_id
                    """, Long.class, label);
        }
        if ("CANDIDATE".equals(state)) {
            return jdbc.queryForObject("""
                    INSERT INTO secret_credential_sets
                        (issuer, credential_type, component_state, candidate_locator,
                         fingerprint_key_version, masked_label, first_seen_at, last_seen_at)
                    VALUES ('AWS', 'AWS_ACCESS_KEY_PAIR', 'CANDIDATE',
                            decode(md5(random()::text), 'hex'), 'test', ?, now(), now())
                    RETURNING credential_set_id
                    """, Long.class, label);
        }
        return jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint, fingerprint_key_version,
                     masked_label, first_seen_at, last_seen_at)
                VALUES ('AWS', 'AWS_ACCESS_KEY_PAIR', 'CONFIRMED', decode(md5(random()::text), 'hex'), 'test', ?, now(), now())
                RETURNING credential_set_id
                """, Long.class, label);
    }

    private long occurrence(long secretId, long connectionId, long scopeId, String exposure) {
        long occurrenceId = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status, first_seen_at, last_seen_at)
                VALUES (?, ?, ?, 'repo/test.txt', 'L1', 'UNKNOWN', ?, 'UNKNOWN', 'PRESENT', now(), now())
                RETURNING occurrence_id
                """, Long.class, secretId, connectionId, scopeId, exposure);
        String origin = jdbc.queryForObject(
                "SELECT response_origin FROM secret_connection_scopes WHERE scope_id = ?",
                String.class, scopeId);
        if ("ABNORMAL".equals(exposure) && !"UNCLASSIFIED".equals(origin)) {
            seedAssessment(occurrenceId, origin);
        }
        return occurrenceId;
    }

    private void grant(long userId, String role, Long connectionId) {
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, connection_id, granted_by_user_id, grant_source)
                VALUES (?, ?, ?, ?, 'MANUAL')
                """, userId, role, connectionId, securityUser);
    }

    private void membership(long userId, String team) {
        jdbc.update("""
                INSERT INTO secret_team_memberships (user_id, team_name, added_by_user_id)
                VALUES (?, ?, ?)
                """, userId, team, securityUser);
    }

    private void classifyScope(long scopeId, String origin) {
        jdbc.update("""
                UPDATE secret_connection_scopes
                SET response_origin = ?, response_origin_version = 1,
                    response_origin_set_by_user_id = ?, response_origin_set_at = now()
                WHERE scope_id = ?
                """, origin, securityUser, scopeId);
        jdbc.update("""
                INSERT INTO secret_scope_origin_decisions
                    (scope_id, from_origin, to_origin, reason_code, actor_user_id, version)
                VALUES (?, 'UNCLASSIFIED', ?, ?, ?, 1)
                """, scopeId, origin, "TEST".equals(origin) ? "APPROVED_TEST_FIXTURE"
                : "APPROVED_PRODUCTION_SOURCE", securityUser);
        for (Long occurrenceId : jdbc.queryForList("""
                SELECT occurrence_id FROM secret_occurrences
                WHERE scope_id = ? AND exposure_status = 'ABNORMAL'
                """, Long.class, scopeId)) {
            seedAssessment(occurrenceId, origin);
        }
    }

    private void seedAssessment(long occurrenceId, String origin) {
        jdbc.update("""
                UPDATE secret_occurrences SET exposure_assessment_version = 1 WHERE occurrence_id = ?
                """, occurrenceId);
        jdbc.update("""
                INSERT INTO secret_exposure_assessments
                    (occurrence_id, finding_id, finding_rule_id, finding_run_id,
                     from_status, decision, reason_code, scope_origin, actor_user_id, version)
                VALUES (?, ?, 'test-rule', 1, 'UNKNOWN', 'ABNORMAL', ?, ?, ?, 1)
                """, occurrenceId, occurrenceId,
                "TEST".equals(origin) ? "SIMULATED_EXPOSURE" : "UNAPPROVED_SOURCE_LOCATION",
                origin, securityUser);
    }

    private static SecretCaseOpenRequest openRequest(long occurrenceId) {
        return new SecretCaseOpenRequest(occurrenceId, "ASSESSED_EXPOSURE", 1L, 1L);
    }

    private static void assertCode(ErrorCode expected, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(ApiException.class)
                .satisfies(error -> assertThat(((ApiException) error).errorCode()).isEqualTo(expected));
    }
}
