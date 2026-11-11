package com.logssey.secretworker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.logssey.secret.notion.SecretNotionSourceCredentials;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.notion.NotionApprovedScope;
import com.logssey.secretworker.notion.NotionCollectionLimits;
import com.logssey.secretworker.notion.NotionCollector;
import com.logssey.secretworker.notion.NotionSecretJobProcessor;
import com.logssey.secretworker.notion.NotionSourceException;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.CredentialValidationResult;
import com.logssey.secretworker.validation.GitHubPatValidator;
import com.logssey.secretworker.validation.NotionTokenValidator;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

class NotionSecretJobProcessorTest {
  private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
  private static final String PAGE = "11111111-1111-4111-8111-111111111111";
  private static final String OTHER_PAGE = "22222222-2222-4222-8222-222222222222";
  private static final String BLOCK = "33333333-3333-4333-8333-333333333333";
  private static final String OTHER_BLOCK = "44444444-4444-4444-8444-444444444444";
  private static final String TOKEN = "ntn_" + "A".repeat(46);
  private static final String OTHER_TOKEN = "ntn_" + "B".repeat(46);
  private static final String CONFIG_HASH = "a".repeat(64);
  private static JdbcTemplate jdbc;
  private static DataSourceTransactionManager transactions;

  private final List<String> detectedText = new ArrayList<>();
  private NotionCollector collector;
  private NotionTokenValidator validator;
  private GitHubPatValidator github;
  private AwsValidationService aws;
  private SecretJobExecutionService execution;
  private NotionSecretJobProcessor processor;
  private long connectionId;
  private long scopeId;

  @BeforeAll
  static void startDatabase() {
    POSTGRES.start();
    var datasource =
        new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    Flyway.configure().dataSource(datasource).load().migrate();
    jdbc = new JdbcTemplate(datasource);
    transactions = new DataSourceTransactionManager(datasource);
  }

  @AfterAll
  static void stopDatabase() {
    POSTGRES.stop();
  }

  @BeforeEach
  void setUp() {
    jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
    collector = mock(NotionCollector.class);
    org.mockito.Mockito.when(collector.observed(org.mockito.ArgumentMatchers.any())).thenReturn(collector);
    validator = mock(NotionTokenValidator.class);
    github = mock(GitHubPatValidator.class);
    aws = mock(AwsValidationService.class);
    var normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
    var findings =
        new SecretFindingRepository(jdbc, new TransactionTemplate(transactions), normalizer);
    var jobs =
        new SecretJobProperties(
            false,
            Duration.ofSeconds(30),
            Duration.ofMinutes(5),
            10,
            Duration.ofSeconds(1),
            Duration.ofSeconds(8));
    execution = SecretJobTestSupport.execution(jdbc, jobs, transactions);
    var attempts = new SecretValidationAttemptRepository(jdbc, execution);
    SecretContentDetector detector =
        new SecretContentDetector() {
          @Override
          public String engineVersion() {
            return "8.30.1";
          }

          @Override
          public String configHash() {
            return CONFIG_HASH;
          }

          @Override
          public GitleaksScanResult scan(byte[] bytes) {
            String text = new String(bytes, StandardCharsets.UTF_8);
            detectedText.add(text);
            List<GitleaksFinding> matches =
                text.startsWith("NOTION_TOKEN=")
                    ? List.of(new GitleaksFinding("notion-api-token", 1, 1, 14, 63))
                    : text.equals("unattributed")
                        ? List.of(new GitleaksFinding("unknown-rule", 1, 1, 1, 12))
                        : List.of();
            return new GitleaksScanResult(engineVersion(), configHash(), matches);
          }
        };
    processor =
        new NotionSecretJobProcessor(
            jdbc,
            collector,
            SecretNotionSourceCredentials.file(Path.of("unused-synthetic-notion-source-token")),
            detector,
            findings,
            normalizer,
            attempts,
            aws,
            github,
            validator,
            jobs);
    connectionId =
        jdbc.queryForObject(
            """
            INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
            VALUES('NOTION','approved pages','notion-internal:default','ACTIVE',1)
            RETURNING connection_id
            """,
            Long.class);
    scopeId = addScope(PAGE);
  }

  @Test
  void preservesFindingsWhenAnotherApprovedPageIsInaccessible() {
    addScope(OTHER_PAGE);
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          if (scope.pageId().equals(OTHER_PAGE)) {
            return result(
                NotionCollector.Status.FAILED,
                false,
                NotionSourceException.Code.ACCESS_DENIED,
                null,
                0);
          }
          emit(sink, PAGE, null, "", true, null, null);
          emit(sink, PAGE, BLOCK, content(TOKEN), true, null, null);
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 2);
        });
    var job = runSuccessfully();

    assertThat(runStatus(job)).isEqualTo("PARTIAL");
    assertThat(
            jdbc.queryForList(
                "SELECT collection_status FROM secret_run_scopes ORDER BY run_scope_id",
                String.class))
        .containsExactly("SUCCEEDED", "FAILED");
    assertThat(count("secret_credential_sets")).isEqualTo(1);
    assertThat(count("secret_occurrences")).isEqualTo(1);
    assertThat(
            jdbc.queryForObject("SELECT source_object_ref FROM secret_occurrences", String.class))
        .isEqualTo(sourceRef(PAGE, BLOCK));
  }

  @Test
  void anEmptyPageCompletesWithZeroKeysAndOneScannedTitle() {
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, PAGE, null, "", true, null, null);
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 1);
        });
    var job = runSuccessfully();

    assertThat(runStatus(job)).isEqualTo("SUCCEEDED");
    assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class))
        .isEqualTo(1);
    assertThat(count("secret_credential_sets")).isZero();
    assertThat(count("secret_validation_attempts")).isZero();
    verifyNoInteractions(validator, github, aws);
  }

  @Test
  void theSameKeyInTwoBlocksHasOneIdentityAndTwoLocations() {
    approveValidation();
    when(validator.enabled()).thenReturn(true);
    when(validator.validate(TOKEN))
        .thenReturn(
            new CredentialValidationResult("VALID", "AUTHENTICATED", Instant.now(), 200, null));
    twoBlocks(false);
    var job = runSuccessfully();

    assertThat(runStatus(job)).isEqualTo("SUCCEEDED");
    assertThat(count("secret_credential_sets")).isEqualTo(1);
    assertThat(count("secret_occurrences")).isEqualTo(2);
    assertThat(count("secret_validation_attempts")).isEqualTo(1);
    verify(validator).validate(TOKEN);
    assertThat(
            jdbc.queryForList(
                "SELECT source_object_ref FROM secret_occurrences ORDER BY source_object_ref",
                String.class))
        .containsExactly(sourceRef(PAGE, BLOCK), sourceRef(PAGE, OTHER_BLOCK));
    assertThat(
            jdbc.queryForList(
                    "SELECT to_jsonb(k)::text FROM secret_credential_sets k", String.class)
                .toString())
        .doesNotContain(TOKEN);
  }

  @Test
  void anUncheckedFixtureDoesNotPreventValidationInAnotherApprovedScope() {
    addScope(OTHER_PAGE);
    approveValidation();
    jdbc.update(
        "UPDATE secret_connection_scopes SET synthetic_fixture=true WHERE scope_id=?", scopeId);
    when(validator.enabled()).thenReturn(true);
    when(validator.validate(TOKEN))
        .thenReturn(
            new CredentialValidationResult("VALID", "AUTHENTICATED", Instant.now(), 200, null));
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, scope.pageId(), BLOCK, content(TOKEN), true, null, null);
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 1);
        });
    runSuccessfully();

    verify(validator).validate(TOKEN);
    assertThat(
            jdbc.queryForList(
                "SELECT result FROM secret_validation_attempts ORDER BY attempt_id", String.class))
        .containsExactly("UNCHECKED", "VALID");
    assertThat(
            jdbc.queryForList(
                "SELECT reason_code FROM secret_validation_attempts ORDER BY attempt_id",
                String.class))
        .containsExactly("SYNTHETIC_FIXTURE", "AUTHENTICATED");
    assertThat(count("secret_credential_sets")).isEqualTo(1);
    assertThat(count("secret_occurrences")).isEqualTo(2);
  }

  @Test
  void reorderingBlocksRetainsOccurrenceIdsOnTheNextScan() {
    twoBlocks(false);
    runSuccessfully();
    Map<String, Long> original = occurrences();
    twoBlocks(true);
    runSuccessfully();

    assertThat(occurrences()).isEqualTo(original);
    assertThat(count("secret_credential_sets")).isEqualTo(1);
    assertThat(count("secret_occurrences")).isEqualTo(2);
    assertThat(count("secret_findings")).isEqualTo(4);
  }

  @ParameterizedTest
  @EnumSource(
      value = NotionSourceException.Code.class,
      names = {"CONTENT_CHANGED", "UNSUPPORTED_BLOCK"})
  void incompleteOrChangedContentNeverMarksAPreviousKeyMissing(NotionSourceException.Code gap) {
    twoBlocks(false);
    runSuccessfully();
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, PAGE, null, "", false, null, "NOTION_" + gap.name());
          return result(NotionCollector.Status.PARTIAL, false, gap, null, 1);
        });
    var job = runSuccessfully();

    assertThat(runStatus(job)).isEqualTo("PARTIAL");
    assertThat(jdbc.queryForList("SELECT presence_status FROM secret_occurrences", String.class))
        .containsOnly("UNKNOWN");
    assertThat(count("secret_occurrences")).isEqualTo(2);
    assertThat(count("secret_findings")).isEqualTo(2);
    assertThat(
            jdbc.queryForObject(
                "SELECT failure_code FROM secret_run_scopes WHERE run_id=?",
                String.class,
                job.runId()))
        .isEqualTo("NOTION_" + gap.name());
  }

  @Test
  void aCompleteWalkWithNoKeysDoesNotProveEarlierNotionLocationsWereRemoved() {
    twoBlocks(false);
    runSuccessfully();
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, PAGE, null, "", true, null, null);
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 1);
        });
    var job = runSuccessfully();

    assertThat(runStatus(job)).isEqualTo("SUCCEEDED");
    assertThat(
            jdbc.queryForObject(
                "SELECT collection_status FROM secret_run_scopes WHERE run_id=?",
                String.class,
                job.runId()))
        .isEqualTo("SUCCEEDED");
    assertThat(jdbc.queryForList("SELECT presence_status FROM secret_occurrences", String.class))
        .containsOnly("UNKNOWN");
    assertThat(count("secret_occurrences")).isEqualTo(2);
    assertThat(count("secret_findings")).isEqualTo(2);
  }

  @Test
  void manualRevalidationWalksTheApprovedPageButOnlyUsesTheExactTargetBlock() {
    twoBlocks(false);
    runSuccessfully();
    long target =
        jdbc.queryForObject(
            "SELECT occurrence_id FROM secret_occurrences WHERE source_object_ref=?",
            Long.class,
            sourceRef(PAGE, BLOCK));
    long actor = approveValidation();
    when(validator.enabled()).thenReturn(true);
    when(validator.validate(TOKEN))
        .thenReturn(
            new CredentialValidationResult("VALID", "AUTHENTICATED", Instant.now(), 200, null));
    detectedText.clear();
    var pages = new ArrayList<String>();
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          pages.add(scope.pageId());
          emit(sink, PAGE, OTHER_BLOCK, content(OTHER_TOKEN), true, null, null);
          emit(sink, PAGE, BLOCK, content(TOKEN), true, null, null);
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 2);
        });
    var job = newRun();
    jdbc.update(
        """
        UPDATE secret_jobs SET kind='REVALIDATE',purpose='CREDENTIAL_VALIDITY',requested_by_user_id=?,
        target_occurrence_id=?,expected_context=jsonb_build_object('contextVersion',
          (SELECT context_version FROM secret_validation_context WHERE occurrence_id=?)) WHERE job_id=?
        """,
        actor,
        target,
        target,
        job.jobId());
    processor.process(job, execution);
    assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();

    assertThat(pages).containsExactly(PAGE);
    assertThat(detectedText).containsExactly(content(TOKEN));
    verify(validator).validate(TOKEN);
    assertThat(count("secret_credential_sets")).isEqualTo(1);
    assertThat(
            jdbc.queryForObject(
                "SELECT result FROM secret_validation_attempts WHERE job_id=?",
                String.class,
                job.jobId()))
        .isEqualTo("VALID");
    verifyNoInteractions(github, aws);
  }

  @Test
  void losingTheLeaseBetweenCollectionAndCallbackPreventsFindingWrites() {
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()-interval '1 second'");
          emit(sink, PAGE, BLOCK, content(TOKEN), true, null, null);
          throw new AssertionError("An expired callback must fail");
        });
    var job = newRun();

    assertThatThrownBy(() -> processor.process(job, execution))
        .isInstanceOfSatisfying(
            SecretJobFailure.class,
            error -> assertThat(error.code()).isEqualTo(SecretJobFailureCode.LEASE_EXPIRED));
    assertThat(count("secret_findings")).isZero();
    assertThat(count("secret_validation_attempts")).isZero();
    verifyNoInteractions(validator, github, aws);
  }

  @Test
  void revokingAnApprovedScopePreventsTheNextProviderRequest() {
    var sent = new AtomicInteger();
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          sent.incrementAndGet();
          jdbc.update(
              "UPDATE secret_connection_scopes SET enabled=false WHERE scope_id=?", scopeId);
          guard.run();
          sent.incrementAndGet();
          throw new AssertionError("A revoked scope must block the next request");
        });
    var job = newRun();

    assertThatThrownBy(() -> processor.process(job, execution))
        .isInstanceOfSatisfying(
            SecretJobFailure.class,
            error -> assertThat(error.code()).isEqualTo(SecretJobFailureCode.SOURCE_ACCESS_DENIED));
    assertThat(sent).hasValue(1);
    assertThat(count("secret_findings")).isZero();
    verifyNoInteractions(validator, github, aws);
  }

  @Test
  void aSourceRateLimitPersistsCooldownAndReschedulesWithoutCallingTheValidator() {
    approveValidation();
    when(validator.enabled()).thenReturn(true);
    Instant until = Instant.now().plusSeconds(120).truncatedTo(ChronoUnit.MICROS);
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, PAGE, BLOCK, content(TOKEN), false, until, "NOTION_RATE_LIMITED");
          return result(
              NotionCollector.Status.PARTIAL,
              false,
              NotionSourceException.Code.RATE_LIMITED,
              until,
              1);
        });
    var job = newRun();
    assertThatThrownBy(() -> processor.process(job, execution))
        .isInstanceOfSatisfying(
            SecretJobFailure.class,
            error -> {
              assertThat(error.code()).isEqualTo(SecretJobFailureCode.SOURCE_RATE_LIMITED);
              assertThat(
                      execution.fail(
                          job.jobId(), job.leaseToken(), error.code(), error.retryable()))
                  .isTrue();
            });

    assertThat(
            jdbc.queryForObject(
                    "SELECT source_retry_at FROM secret_connections WHERE connection_id=?",
                    OffsetDateTime.class,
                    connectionId)
                .toInstant())
        .isEqualTo(until);
    assertThat(
            jdbc.queryForObject(
                "SELECT source_retry_reason FROM secret_connections WHERE connection_id=?",
                String.class,
                connectionId))
        .isEqualTo("NOTION_RATE_LIMITED");
    assertThat(
            jdbc.queryForObject(
                    "SELECT available_at FROM secret_jobs WHERE job_id=?",
                    OffsetDateTime.class,
                    job.jobId())
                .toInstant())
        .isAfterOrEqualTo(until);
    assertThat(
            jdbc.queryForObject(
                "SELECT status FROM secret_jobs WHERE job_id=?", String.class, job.jobId()))
        .isEqualTo("PENDING");
    assertThat(execution.claimNextJob("NOTION")).isEmpty();
    assertThat(count("secret_findings")).isEqualTo(1);
    assertThat(
            jdbc.queryForObject("SELECT reason_code FROM secret_validation_attempts", String.class))
        .isEqualTo("RATE_LIMITED");
    org.mockito.Mockito.verify(validator, org.mockito.Mockito.never()).validate(any());
  }

  @Test
  void detectorFindingsWithoutNormalizedCredentialsKeepTheRunPartial() {
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, PAGE, BLOCK, "unattributed", true, null, null);
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 1);
        });
    var job = runSuccessfully();

    assertThat(runStatus(job)).isEqualTo("PARTIAL");
    assertThat(jdbc.queryForObject("SELECT status FROM secret_tool_runs", String.class))
        .isEqualTo("PARTIAL");
    assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_run_scopes", String.class))
        .isEqualTo("DETECTOR_NORMALIZATION_INCOMPLETE");
    assertThat(count("secret_credential_sets")).isZero();
  }

  private void twoBlocks(boolean reversed) {
    stubCollector(
        (scope, sink, guard) -> {
          guard.run();
          emit(sink, PAGE, null, "", true, null, null);
          for (String block :
              reversed ? List.of(OTHER_BLOCK, BLOCK) : List.of(BLOCK, OTHER_BLOCK)) {
            emit(sink, PAGE, block, content(TOKEN), true, null, null);
          }
          return result(NotionCollector.Status.SUCCEEDED, true, null, null, 3);
        });
  }

  private void stubCollector(CollectionAction action) {
    doAnswer(
            invocation ->
                action.collect(
                    invocation.getArgument(0),
                    invocation.getArgument(2),
                    invocation.getArgument(3)))
        .when(collector)
        .collect(
            any(NotionApprovedScope.class),
            any(NotionCollectionLimits.class),
            any(NotionCollector.ContentSink.class),
            any(Runnable.class));
  }

  private static void emit(
      NotionCollector.ContentSink sink,
      String page,
      String block,
      String text,
      boolean comparable,
      Instant retryAt,
      String failure) {
    sink.accept(
        new NotionCollector.Source(
            page, block, "notion-v1:synthetic-version", comparable, retryAt, failure),
        text.getBytes(StandardCharsets.UTF_8));
  }

  private static NotionCollector.Result result(
      NotionCollector.Status status,
      boolean comparable,
      NotionSourceException.Code gap,
      Instant retryAt,
      int objects) {
    return new NotionCollector.Result(
        status,
        objects,
        0,
        gap == null ? List.of() : List.of(new NotionCollector.Gap(null, gap)),
        comparable,
        retryAt,
        0,
        false);
  }

  private long addScope(String page) {
    return jdbc.queryForObject(
        """
        INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,
            approved_ref,history_limit,enabled)
        VALUES(?,?,1,'NOTION_PAGE_CONTENT',?,'CURRENT_VERSION_ONLY',true) RETURNING scope_id
        """,
        Long.class,
        connectionId,
        "page-" + page,
        "notion://pages/" + page);
  }

  private ClaimedSecretJob newRun() {
    OffsetDateTime now = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    long jobId =
        jdbc.queryForObject(
            """
            INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status)
            VALUES('FULL_SCAN',?,?,?,0,3,'PENDING') RETURNING job_id
            """,
            Long.class,
            connectionId,
            now,
            now);
    long runId =
        jdbc.queryForObject(
            """
            INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,
                collection_status,detection_status,validation_status,result_status)
            VALUES(?,?,'MANUAL',1,?,?,'PENDING','PENDING','PENDING','PENDING') RETURNING run_id
            """,
            Long.class,
            jobId,
            connectionId,
            now,
            now);
    jdbc.update(
        """
        INSERT INTO secret_run_scopes(run_id,scope_id,collection_status)
        SELECT ?,scope_id,'PENDING' FROM secret_connection_scopes WHERE connection_id=? AND enabled ORDER BY scope_id
        """,
        runId,
        connectionId);
    return execution.claimNextJob("NOTION").orElseThrow();
  }

  private ClaimedSecretJob runSuccessfully() {
    var job = newRun();
    processor.process(job, execution);
    assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
    return job;
  }

  private long approveValidation() {
    long actor =
        jdbc.queryForObject(
            """
            INSERT INTO dashboard_users(login_id,password_hash,display_name,role)
            VALUES('notion-worker-approver','h','Approver','ADMIN')
            ON CONFLICT(login_id) DO UPDATE SET display_name='Approver' RETURNING user_id
            """,
            Long.class);
    jdbc.update(
        """
        INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)
        VALUES(?,'SECURITY',?,?,'MANUAL') ON CONFLICT DO NOTHING
        """,
        actor,
        connectionId,
        actor);
    jdbc.update(
        "UPDATE secret_connections SET"
            + " validation_enabled=true,validation_profile_version='credential-validation-v1' WHERE"
            + " connection_id=?",
        connectionId);
    jdbc.update(
        """
        UPDATE secret_connection_scopes SET validation_approved=true,
            validation_profile_version='credential-validation-v1',validation_approved_by_user_id=?,validation_approved_at=now()
        WHERE connection_id=?
        """,
        actor,
        connectionId);
    return actor;
  }

  private static String content(String token) {
    return "NOTION_TOKEN=" + token;
  }

  private static String sourceRef(String page, String block) {
    return "notion/pages/" + page + "/blocks/" + block;
  }

  private static long count(String table) {
    return jdbc.queryForObject("SELECT count(*) FROM " + table, Long.class);
  }

  private static String runStatus(ClaimedSecretJob job) {
    return jdbc.queryForObject(
        "SELECT result_status FROM secret_scan_runs WHERE run_id=?", String.class, job.runId());
  }

  private static Map<String, Long> occurrences() {
    var result = new java.util.LinkedHashMap<String, Long>();
    jdbc.query(
        "SELECT source_object_ref,occurrence_id FROM secret_occurrences ORDER BY source_object_ref",
        (org.springframework.jdbc.core.RowCallbackHandler)
            row -> result.put(row.getString(1), row.getLong(2)));
    return result;
  }

  @FunctionalInterface
  private interface CollectionAction {
    NotionCollector.Result collect(
        NotionApprovedScope scope, NotionCollector.ContentSink sink, Runnable guard);
  }
}
