package com.logssey.remediation;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.iac.finding.FindingUpdateRequest;
import com.logssey.iac.finding.IacFindingRepository;
import com.logssey.iac.finding.IacFindingService;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import java.util.concurrent.*;
import static org.assertj.core.api.Assertions.*;

class ActionRecordServiceTest {
    static final PostgreSQLContainer DB = new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;
    static DataSourceTransactionManager tx;
    ActionRecordService service;

    @BeforeAll static void start() {
        DB.start();
        var ds = new DriverManagerDataSource(DB.getJdbcUrl(), DB.getUsername(), DB.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        jdbc = new JdbcTemplate(ds);
        tx = new DataSourceTransactionManager(ds);
    }
    @AfterAll static void stop() { DB.stop(); }
    @BeforeEach void seed() {
        jdbc.execute("TRUNCATE dashboard_users, reach_targets, iac_jobs, iac_data_assets RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES ('admin','h','담당자','ADMIN'), ('colleague','h','팀원','ADMIN')");
        jdbc.update("INSERT INTO iac_jobs(kind,trigger_type,status) VALUES ('CHECK_DRIFT','SCHEDULED','SUCCEEDED')");
        jdbc.update("""
                INSERT INTO iac_findings(rule_id,source,enforcement,severity,environment,resource_address,fingerprint,last_job_id,first_seen_at,last_seen_at)
                VALUES ('drift.high','DRIFT','WARN','HIGH','DEV','demo.resource','fp',1,now(),now())
                """);
        jdbc.update("INSERT INTO iac_data_assets(arn,kind,tier) VALUES ('demo','SECRET',1)");
        jdbc.update("""
                INSERT INTO iac_attack_paths(fingerprint,entry,target_data_asset_id,tier,severity,environment,hops,length,first_seen_at,last_seen_at)
                VALUES ('path','Internet',1,1,'HIGH','DEV','[]',1,now(),now())
                """);
        jdbc.update("INSERT INTO reach_targets(target_type,app,image_repository,image_digest,display_name) VALUES ('IMAGE','API','demo','sha256:demo','demo')");
        jdbc.update("INSERT INTO reach_scans(target_id,scan_status,trigger_type,requested_by_kind,finished_at) VALUES (1,'SUCCEEDED','MANUAL','SYSTEM',now())");
        jdbc.update("""
                INSERT INTO reach_findings(target_id,purl,component_name,component_version,ecosystem,vulnerability_id,severity,sources,last_scan_id,first_seen_at,last_seen_at)
                VALUES (1,'pkg:maven/demo@1','demo','1','maven','CVE-TEST-1','HIGH',ARRAY['TRIVY'],1,now(),now())
                """);
        jdbc.update("""
                INSERT INTO reach_verdicts(finding_id,scan_id,status,method,summary,engine,evidence_hash,is_current,analyzed_at)
                VALUES (1,1,'REACHABLE','CALLGRAPH','test','{}','h',true,now())
                """);
        service = new ActionRecordService(jdbc, tx);
    }
    static ActionRecordService.Update update(long version, long sourceVersion, Long owner, String state, String note, boolean confirmed) {
        return new ActionRecordService.Update(version, sourceVersion, owner, state, note, confirmed);
    }
    static void error(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).isInstanceOf(ApiException.class).satisfies(ex -> assertThat(((ApiException) ex).errorCode()).isEqualTo(code));
    }
    @Test void readIsNonMutatingAndAllDomainsKeepTheirDetectorState() {
        for (String kind : new String[]{"IMAGE", "IAC_PATH", "IAC_FINDING"}) {
            var initial = service.get("admin", kind, 1);
            assertThat(initial.record().version()).isZero();
            assertThat(initial.history()).isEmpty();
            var saved = service.save("admin", kind, 1, update(0, 0, 2L, "RECORDED", "  수정 후 재검사 요청  ", true));
            assertThat(saved.record().version()).isEqualTo(1);
            assertThat(saved.record().note()).isEqualTo("수정 후 재검사 요청");
            assertThat(saved.history()).hasSize(1);
            assertThat(saved.history().getFirst().actorName()).isEqualTo("담당자");
            assertThat(saved.history().getFirst().recordedAt()).isNotNull();
        }
        assertThat(jdbc.queryForObject("SELECT status FROM reach_verdicts WHERE is_current", String.class)).isEqualTo("REACHABLE");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_findings", String.class)).isEqualTo("OPEN");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_attack_paths", String.class)).isEqualTo("OPEN");
        assertThat(jdbc.queryForObject("SELECT assignee_user_id FROM iac_findings", Long.class)).isEqualTo(2);
    }
    @Test void noRecordsCreatedByReadsOrRejectedWrites() {
        service.get("admin", "IMAGE", 1);
        error(() -> service.save("admin", "IMAGE", 1, update(0, 0, 999L, "IN_PROGRESS", "", false)), ErrorCode.INVALID_INPUT);
        error(() -> service.save("admin", "IMAGE", 1, update(7, 0, 1L, "IN_PROGRESS", "", false)), ErrorCode.CONFLICT);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_action_records", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM security_action_history", Long.class)).isZero();
    }
    @Test void authorizationAndCompletionRequirements() {
        error(() -> service.get(null, "IMAGE", 1), ErrorCode.UNAUTHENTICATED);
        error(() -> service.get("nobody", "IMAGE", 1), ErrorCode.FORBIDDEN);
        error(() -> service.save("nobody", "IMAGE", 1, update(0, 0, 1L, "IN_PROGRESS", "", false)), ErrorCode.FORBIDDEN);
        error(() -> service.get("admin", "SECRET", 1), ErrorCode.INVALID_INPUT);
        error(() -> service.get("admin", "IMAGE", 999), ErrorCode.NOT_FOUND);
        error(() -> service.save("admin", "IMAGE", 1, update(0, 0, null, "IN_PROGRESS", "", false)), ErrorCode.INVALID_INPUT);
        error(() -> service.save("admin", "IMAGE", 1, update(0, 0, 1L, "AWAITING_CHECK", " ", false)), ErrorCode.INVALID_INPUT);
        error(() -> service.save("admin", "IMAGE", 1, update(0, 0, 1L, "RECORDED", "done", false)), ErrorCode.INVALID_INPUT);
        error(() -> service.save("admin", "IMAGE", 1, update(0, 0, 1L, "RESOLVED", "done", true)), ErrorCode.INVALID_INPUT);
        error(() -> service.save("admin", "IMAGE", 1, update(0, 0, 1L, "IN_PROGRESS", "x".repeat(2001), false)), ErrorCode.INVALID_INPUT);
    }
    @Test void legacyIacAssignmentCannotBeOverwrittenByAStaleForm() {
        service.save("admin", "IAC_FINDING", 1, update(0, 0, 1L, "IN_PROGRESS", "시작", false));
        var legacy = new IacFindingService(new IacFindingRepository(jdbc), tx);
        legacy.update(1, new FindingUpdateRequest(2L, false, null, 1L), "admin");
        error(() -> service.save("admin", "IAC_FINDING", 1, update(1, 1, 1L, "AWAITING_CHECK", "완료", false)), ErrorCode.CONFLICT);
        var read = service.get("admin", "IAC_FINDING", 1);
        assertThat(read.record().assigneeUserId()).isEqualTo(2);
        assertThat(read.source().version()).isEqualTo(2);
        assertThat(read.history()).hasSize(1);
    }
    @Test void concurrentFirstSavesProduceOneRecordAndOneConflict() throws Exception {
        try (var pool = Executors.newFixedThreadPool(2)) {
            var ready = new CountDownLatch(2);
            var go = new CountDownLatch(1);
            Callable<String> save = () -> {
                ready.countDown(); go.await(10, TimeUnit.SECONDS);
                try { service.save("admin", "IMAGE", 1, update(0, 0, 1L, "IN_PROGRESS", "", false)); return "saved"; }
                catch (ApiException ex) { return ex.errorCode().name(); }
            };
            var first = pool.submit(save); var second = pool.submit(save);
            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue(); go.countDown();
            assertThat(java.util.List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS))).containsExactlyInAnyOrder("saved", "CONFLICT");
            assertThat(service.get("admin", "IMAGE", 1).history()).hasSize(1);
        }
    }

    long postActionImage(boolean present) {
        long scan=jdbc.queryForObject("""
            INSERT INTO reach_scans(target_id,scan_status,trigger_type,requested_by_kind,tools,stages,started_at,finished_at)
            VALUES (1,'SUCCEEDED','MANUAL','SYSTEM','{"trivy":"test"}',
              '[{"name":"SBOM","status":"SUCCEEDED"},{"name":"MATCH","status":"SUCCEEDED"}]',now(),now()) RETURNING scan_id
            """,Long.class);
        jdbc.update("INSERT INTO reach_sboms(scan_id,content_gzip,content_sha256,component_count) VALUES (?,decode('00','hex'),'hash',1)",scan);
        if(present) jdbc.update("""
            INSERT INTO reach_verdicts(finding_id,scan_id,status,method,summary,engine,evidence_hash,is_current,analyzed_at)
            VALUES (1,?,'UNREACHABLE','CALLGRAPH','not called but still vulnerable','{}','h',false,now())
            """,scan);
        return scan;
    }
    void recordAction(String kind) { service.save("admin",kind,1,update(0,0,1L,"RECORDED","시연 데이터 수정",true)); }
    @Test void imageVerificationRequiresPostActionScanAndExplicitLink() {
        recordAction("IMAGE");
        assertThat(service.get("admin","IMAGE",1).verification().status()).isEqualTo("PENDING");
        error(()->service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,1)),ErrorCode.INVALID_INPUT);
        long scan=postActionImage(false);
        var linked=service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,scan));
        assertThat(linked.verification().status()).isEqualTo("NOT_FOUND");
        assertThat(linked.verification().checkId()).isEqualTo(scan);
        assertThat(jdbc.queryForObject("SELECT status FROM reach_verdicts WHERE is_current",String.class)).isEqualTo("REACHABLE");
        var changed=service.save("admin","IMAGE",1,update(1,0,1L,"RECORDED","다시 수정",true));
        assertThat(changed.verification().status()).isEqualTo("PENDING");
        error(()->service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,scan)),ErrorCode.CONFLICT);
    }
    @Test void imageUnreachableReviewIsStillFoundAndNewerFailureInvalidatesOlderAbsence() {
        recordAction("IMAGE");
        long found=postActionImage(true);
        assertThat(service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,found)).verification().status()).isEqualTo("FOUND");
        long absent=postActionImage(false);
        assertThat(service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,absent)).verification().status()).isEqualTo("NOT_FOUND");
        jdbc.update("INSERT INTO reach_scans(target_id,scan_status,trigger_type,requested_by_kind,failure_code,finished_at) VALUES (1,'FAILED','MANUAL','SYSTEM','DEMO',now())");
        assertThat(service.get("admin","IMAGE",1).verification().status()).isEqualTo("UNCONFIRMED");
    }
    @Test void missingStageOrScannerDoesNotProveAbsenceAndOtherRepositoryIsRejected() {
        recordAction("IMAGE"); long scan=postActionImage(false);
        jdbc.update("UPDATE reach_scans SET tools='{}' WHERE scan_id=?",scan);
        assertThat(service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,scan)).verification().status()).isEqualTo("UNCONFIRMED");
        jdbc.update("UPDATE reach_scans SET tools='{\"trivy\":\"test\"}',stages='[]' WHERE scan_id=?",scan);
        assertThat(service.get("admin","IMAGE",1).verification().status()).isEqualTo("UNCONFIRMED");
        jdbc.update("INSERT INTO reach_targets(target_type,app,image_repository,image_digest,display_name) VALUES ('IMAGE','API','another','sha256:other','other')");
        jdbc.update("UPDATE reach_scans SET target_id=2 WHERE scan_id=?",scan);
        error(()->service.link("admin","IMAGE",1,new ActionRecordService.LinkCheck(1L,scan)),ErrorCode.INVALID_INPUT);
    }
    @Test void iacAbsenceNeedsSpecificSuccessfulPostActionEvidence() {
        recordAction("IAC_PATH");
        jdbc.update("UPDATE iac_attack_paths SET status='CLOSED' WHERE path_id=1");
        assertThat(service.get("admin","IAC_PATH",1).verification().status()).isEqualTo("PENDING");
        long job=jdbc.queryForObject("INSERT INTO iac_jobs(kind,trigger_type,status,finished_at) VALUES ('ENRICH_GRAPH','MANUAL','SUCCEEDED',now()) RETURNING job_id",Long.class);
        jdbc.update("UPDATE iac_attack_paths SET checked_job_id=? WHERE path_id=1",job);
        assertThat(service.get("admin","IAC_PATH",1).verification().status()).isEqualTo("NOT_FOUND");
        jdbc.update("UPDATE iac_jobs SET status='FAILED' WHERE job_id=?",job);
        assertThat(service.get("admin","IAC_PATH",1).verification().status()).isEqualTo("UNCONFIRMED");
        jdbc.update("UPDATE iac_jobs SET status='SUCCEEDED' WHERE job_id=?",job);
        jdbc.update("UPDATE iac_attack_paths SET status='OPEN' WHERE path_id=1");
        assertThat(service.get("admin","IAC_PATH",1).verification().status()).isEqualTo("FOUND");
        jdbc.update("INSERT INTO iac_jobs(kind,trigger_type,status,finished_at) VALUES('ENRICH_GRAPH','MANUAL','FAILED',now())");
        assertThat(service.get("admin","IAC_PATH",1).verification().status()).isEqualTo("UNCONFIRMED");
    }
    @Test void commonListRespectsOwnerAndDomainWithoutSecretAuthorizationBypass() {
        recordAction("IMAGE"); recordAction("IAC_FINDING");
        assertThat(service.list("admin","IMAGE","ME",0).total()).isEqualTo(1);
        assertThat(service.list("colleague","IMAGE","ME",0).total()).isZero();
        jdbc.update("UPDATE iac_findings SET assignee_user_id=NULL WHERE finding_id=1");
        assertThat(service.list("admin","IAC","ME",0).total()).isZero();
        assertThat(service.list("admin","IAC","UNASSIGNED",0).total()).isEqualTo(1);
        error(()->service.list("admin","SECRET","ALL",0),ErrorCode.INVALID_INPUT);
        error(()->service.list("nobody","IAC","ALL",0),ErrorCode.FORBIDDEN);
    }
}
