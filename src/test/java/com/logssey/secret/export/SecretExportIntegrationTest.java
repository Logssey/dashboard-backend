package com.logssey.secret.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.query.SecretInventoryFilters;
import com.logssey.secret.query.SecretLocationRepository;
import com.logssey.secret.query.SecretLocationService;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import tools.jackson.databind.json.JsonMapper;

/** 화면과 같은 권한 규칙을 따르는지, 결과에 원문·HMAC·본문이 없는지 실제 DB로 확인한다. */
class SecretExportIntegrationTest {
    static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    static final SecureRandom RANDOM = new SecureRandom();
    static final List<String> FORMATS = List.of("sarif", "logssey-json", "gitleaks");
    static JdbcTemplate jdbc;
    static TransactionTemplate tx;

    final JsonMapper json = JsonMapper.builder().build();
    SecretLocationService inventory;
    SecretExportService exports;
    long security, remediator, operations, other;

    // 테스트마다 새로 만드는 가짜 값. 실제 키가 아니다.
    String fakeAwsKey, fakeGithubToken, hmacHex, notionBodyMarker, slackBodyMarker, privateMarker;
    String page, block;

    @BeforeAll static void database() {
        POSTGRES.start();
        var ds = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        jdbc = new JdbcTemplate(ds);
        tx = new TransactionTemplate(new DataSourceTransactionManager(ds));
        tx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }

    @AfterAll static void close() { POSTGRES.stop(); }

    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        security = user("security"); remediator = user("remediator"); operations = user("operations"); other = user("other");
        var access = new SecretAccessService(jdbc);
        var snapshots = new SecretReadSnapshots(jdbc, json);
        var commands = new com.logssey.secret.command.SecretCommandExecutor(jdbc, new DataSourceTransactionManager(jdbc.getDataSource()));
        var readiness = new com.logssey.secret.response.SecretLocationReadiness(jdbc, access);
        var workflow = new com.logssey.secret.response.SecretLocationWorkflow(jdbc, access, commands, snapshots, readiness);
        var lifecycle = new com.logssey.secret.lifecycle.SecretLifecycleService(jdbc, access, workflow, commands, snapshots);
        var locations = new SecretLocationRepository(jdbc);
        inventory = new SecretLocationService(locations, snapshots, access, new SecretCoverageService(jdbc, access), readiness, lifecycle);
        exports = new SecretExportService(access, snapshots, locations, new SecretExportRepository(jdbc), json);

        fakeAwsKey = "AKIA" + random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16);
        fakeGithubToken = "ghp_" + random("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 36);
        hmacHex = HexFormat.of().formatHex(bytes(32));
        notionBodyMarker = "notion-body-" + UUID.randomUUID();
        slackBodyMarker = "slack-body-" + UUID.randomUUID();
        privateMarker = "private-" + UUID.randomUUID();
        page = UUID.randomUUID().toString();
        block = UUID.randomUUID().toString();
    }

    @Test void securityExportsEveryFormatWithoutRawValuesHmacOrBodies() {
        var fixture = githubAndNotionKey();
        grant(security, "SECURITY", fixture.github());
        grant(security, "SECURITY", fixture.notion());
        String snapshot = snapshot("security", filter(null));

        for (String format : FORMATS) {
            var file = exports.export("security", format, filter(null), null, snapshot);
            String body = new String(file.body(), StandardCharsets.UTF_8);
            assertNoSecretMaterial(body);
            assertThat(file.filename()).matches("logssey-secrets-" + format + "-\\d{4}-\\d{2}-\\d{2}\\.(sarif|json)");
            assertThat(body).contains("AWS ••••1234", "fixtures/config", "notion/pages/" + page);
        }

        Map<?, ?> sarif = json.readValue(exports.export("security", "sarif", filter(null), null, snapshot).body(), Map.class);
        var results = (List<?>) ((Map<?, ?>) ((List<?>) sarif.get("runs")).getFirst()).get("results");
        assertThat(results).hasSize(2);
        assertThat(results.toString()).contains("physicalLocation", "startLine=4", "logicalLocations", "blocks/" + block,
                "exposureRange=BROAD");

        List<?> gitleaks = json.readValue(exports.export("security", "gitleaks", filter(null), null, snapshot).body(), List.class);
        assertThat(gitleaks).hasSize(2).allSatisfy(item -> assertThat(((Map<?, ?>) item).get("Secret")).isEqualTo("AWS ••••1234"));

        var audits = jdbc.queryForList("SELECT actor_user_id,target_type,safe_changes::text AS changes,occurred_at FROM secret_audit_events WHERE event_type='SECRETS_EXPORTED' ORDER BY audit_id");
        assertThat(audits).hasSize(5);
        assertThat(audits.getFirst()).containsEntry("actor_user_id", security).containsEntry("target_type", "INVENTORY_EXPORT");
        assertThat(audits.getFirst().get("occurred_at")).isNotNull();
        assertThat(audits.getFirst().get("changes").toString()).contains("\"format\": \"sarif\"", "\"keyCount\": 1",
                "\"locationCount\": 2", "\"origin\": \"PRODUCTION\"", "\"hasSearch\": \"false\"");
        audits.forEach(row -> assertNoSecretMaterial(row.get("changes").toString()));
    }

    @Test void remediatorExportsOnlyAssignedLocations() {
        var fixture = githubAndNotionKey();
        grant(remediator, "REMEDIATOR", fixture.github());
        grant(remediator, "REMEDIATOR", fixture.notion());
        assign(fixture.key(), fixture.githubOccurrence(), remediator);

        String snapshot = snapshot("remediator", filter(null));
        for (String format : FORMATS) {
            String body = new String(exports.export("remediator", format, filter(null), null, snapshot).body(), StandardCharsets.UTF_8);
            assertThat(body).contains("fixtures/config").doesNotContain(page, block);
            assertNoSecretMaterial(body);
        }
        Map<?, ?> logssey = json.readValue(exports.export("remediator", "logssey-json", filter(null), null, snapshot).body(), Map.class);
        assertThat(logssey.get("locationCount")).isEqualTo(1);
        assertThat(logssey.get("restrictedCoverage")).isEqualTo(true);
    }

    @Test void operationsAndUngrantedUsersCannotExport() {
        var fixture = githubAndNotionKey();
        grant(operations, "OPERATIONS", fixture.github());
        String anySnapshot = UUID.randomUUID().toString();
        assertCode(ErrorCode.FORBIDDEN, () -> exports.export("operations", "sarif", filter(null), null, anySnapshot));
        assertCode(ErrorCode.FORBIDDEN, () -> exports.export("other", "sarif", filter(null), null, anySnapshot));
        assertCode(ErrorCode.UNAUTHENTICATED, () -> exports.export(null, "sarif", filter(null), null, anySnapshot));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_audit_events WHERE event_type='SECRETS_EXPORTED'", Long.class)).isZero();
    }

    @Test void snapshotOfAnotherUserOrChangedAccessOrFiltersIsRejected() {
        var fixture = githubAndNotionKey();
        grant(security, "SECURITY", fixture.github());
        grant(other, "SECURITY", fixture.github());
        String snapshot = snapshot("security", filter(null));

        assertCode(ErrorCode.NOT_FOUND, () -> exports.export("other", "sarif", filter(null), null, snapshot));
        assertCode(ErrorCode.CONFLICT, () -> exports.export("security", "sarif",
                new SecretInventoryFilters("PRODUCTION", "NOTION", "ALL", "ALL", "VALUE_FINDINGS", "ALL", "ALL", "ALL", "ALL"), null, snapshot));
        grant(security, "SECURITY", fixture.notion());
        assertCode(ErrorCode.CONFLICT, () -> exports.export("security", "sarif", filter(null), null, snapshot));
        assertCode(ErrorCode.INVALID_INPUT, () -> exports.export("security", "csv", filter(null), null, snapshot));
        assertCode(ErrorCode.INVALID_INPUT, () -> exports.export("security", "sarif", filter(null), null, " "));
    }

    @Test void searchTextStaysOutOfFileAndAudit() {
        var fixture = githubAndNotionKey();
        grant(security, "SECURITY", fixture.github());
        String search = "결제";
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias=? WHERE connection_id=?", "결제 서비스", fixture.github());
        String snapshot = snapshot("security", filter(search));
        String body = new String(exports.export("security", "logssey-json", filter(search), null, snapshot).body(), StandardCharsets.UTF_8);
        assertThat(body).contains("\"hasSearch\":\"true\"").doesNotContain("\"q\"");
        String audit = jdbc.queryForObject("SELECT safe_changes::text FROM secret_audit_events WHERE event_type='SECRETS_EXPORTED'", String.class);
        assertThat(audit).contains("\"hasSearch\": \"true\"").doesNotContain(search);
    }

    // ---- fixtures ----

    record Fixture(long key, long github, long notion, long githubOccurrence, long notionOccurrence) { }

    private Fixture githubAndNotionKey() {
        long github = connection("GITHUB"), notion = connection("NOTION");
        long githubScope = scope(github, "github://Logssey/test-find-key/main/fixtures/");
        long notionScope = scope(notion, "notion://pages/" + page);
        long key = jdbc.queryForObject("""
            INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,candidate_locator,fingerprint_key_version,
                masked_label,external_key_ref,owner_ref,purpose_label,first_seen_at,last_seen_at)
            VALUES ('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(?,'hex'),NULL,'test-v1','AWS ••••1234',?,?,?,now(),now())
            RETURNING credential_set_id
            """, Long.class, hmacHex, fakeAwsKey, slackBodyMarker, privateMarker);
        // 원본 경로에 가짜 키를 섞어도 SecretSourceDetails가 마스킹해야 한다.
        long githubOccurrence = occurrence(key, github, githubScope,
                "Logssey/test-find-key/fixtures/config/" + fakeAwsKey + "-" + fakeGithubToken + ".env", "L4-L6", "UNKNOWN");
        // Export the observed branch coordinates, rather than borrowing the mutable scope target.
        jdbc.update("UPDATE secret_occurrences SET source_context_ref='github://Logssey/test-find-key/main/fixtures/',source_context_status='OBSERVED' WHERE occurrence_id=?", githubOccurrence);
        long notionOccurrence = occurrence(key, notion, notionScope, "notion/pages/" + page + "/blocks/" + block, "L1", "BROAD");
        return new Fixture(key, github, notion, githubOccurrence, notionOccurrence);
    }

    private void assertNoSecretMaterial(String text) {
        byte[] hmac = HexFormat.of().parseHex(hmacHex);
        assertThat(text).doesNotContain(fakeAwsKey, fakeGithubToken, hmacHex, hmacHex.toUpperCase(),
                Base64.getEncoder().encodeToString(hmac), Base64.getUrlEncoder().withoutPadding().encodeToString(hmac),
                notionBodyMarker, slackBodyMarker, privateMarker, "private-auth", "private-display");
    }

    private String snapshot(String login, SecretInventoryFilters filters) {
        var page = tx.execute(status -> inventory.inventory(login, filters, 0, 20, null));
        return page.get("snapshotId").toString();
    }

    private SecretInventoryFilters filter(String q) {
        return new SecretInventoryFilters("PRODUCTION", "ALL", "ALL", "ALL", "VALUE_FINDINGS", "ALL", "ALL", "ALL", "ALL", q);
    }

    private long user(String name) {
        return jdbc.queryForObject("""
            INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES (?,'hash',?,'ADMIN') RETURNING user_id
            """, Long.class, name, name);
    }

    private long connection(String provider) {
        return jdbc.queryForObject("""
            INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
            VALUES (?,'private-display','private-auth','ACTIVE',1) RETURNING connection_id
            """, Long.class, provider);
    }

    private long scope(long connection, String approvedRef) {
        long scope = jdbc.queryForObject("""
            INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,
                response_origin,response_origin_set_by_user_id,response_origin_set_at)
            VALUES (?,?,1,?,?,true,'PRODUCTION',?,now()) RETURNING scope_id
            """, Long.class, connection, "scope-" + connection,
                approvedRef.startsWith("github://") ? "GITHUB_REPOSITORY_FILES" : "NOTION_PAGE_CONTENT",
                approvedRef, security);
        // 노션 본문 대신 쓰는 표식: 화면에 보이지 않는 칸에 넣고 결과에 없는지 확인한다.
        jdbc.update("UPDATE secret_connections SET display_name=? WHERE connection_id=? AND provider='NOTION'", notionBodyMarker, connection);
        return scope;
    }

    private long occurrence(long key, long conn, long scope, String sourceRef, String line, String range) {
        return jdbc.queryForObject("""
            INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,
                environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
            VALUES (?,?,?,?,?,'UNKNOWN','ABNORMAL',?,'PRESENT',now(),now()) RETURNING occurrence_id
            """, Long.class, key, conn, scope, sourceRef, line, range);
    }

    private void grant(long user, String role, long connection) {
        jdbc.update("""
            INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)
            VALUES (?,?,?,?,'MANUAL')
            """, user, role, connection, user);
    }

    private void assign(long key, long occurrence, long user) {
        long caseId = jdbc.queryForObject("""
            INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin)
            VALUES (?,?,?,'ASSESSED_EXPOSURE','PRODUCTION') RETURNING case_id
            """, Long.class, key, occurrence, security);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,assigned_user_id) VALUES (?,?,?,?)",
                caseId, occurrence, key, user);
    }

    private static String random(String alphabet, int length) {
        var out = new StringBuilder(length);
        for (int i = 0; i < length; i++) out.append(alphabet.charAt(RANDOM.nextInt(alphabet.length())));
        return out.toString();
    }

    private static byte[] bytes(int length) { var out = new byte[length]; RANDOM.nextBytes(out); return out; }

    private static void assertCode(ErrorCode code, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }
}
