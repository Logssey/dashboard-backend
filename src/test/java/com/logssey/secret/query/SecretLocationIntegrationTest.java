package com.logssey.secret.query;

import java.util.List;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import com.logssey.secret.connection.SecretCoverageService;
import tools.jackson.databind.json.JsonMapper;
import static org.assertj.core.api.Assertions.*;

class SecretLocationIntegrationTest {
    static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;
    static TransactionTemplate tx;
    SecretLocationService service;
    long security,operations,hidden;
    @BeforeAll static void database() {
        POSTGRES.start();
        var ds=new DriverManagerDataSource(POSTGRES.getJdbcUrl(),POSTGRES.getUsername(),POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();
        jdbc=new JdbcTemplate(ds); tx=new TransactionTemplate(new DataSourceTransactionManager(ds));
        tx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }
    @AfterAll static void close() { POSTGRES.stop(); }
    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        security=user("security"); operations=user("operations"); hidden=user("hidden");
        var access=new SecretAccessService(jdbc);var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().build());
        var commands=new com.logssey.secret.command.SecretCommandExecutor(jdbc,new org.springframework.jdbc.datasource.DataSourceTransactionManager(jdbc.getDataSource()));
        var readiness=new com.logssey.secret.response.SecretLocationReadiness(jdbc,access);
        var workflow=new com.logssey.secret.response.SecretLocationWorkflow(jdbc,access,commands,snapshots,readiness);
        var lifecycle=new com.logssey.secret.lifecycle.SecretLifecycleService(jdbc,access,workflow,commands,snapshots);
        service=new SecretLocationService(new SecretLocationRepository(jdbc),snapshots,access,new SecretCoverageService(jdbc,access),readiness,lifecycle);
    }
    @Test void oneKeyKeepsIndependentLocationsWithoutDisclosingOriginalPaths() {
        long conn=connection(); grant(security,"SECURITY",conn); long scope=scope(conn);
        long key=key("CONFIRMED","a1");
        occurrence(key,conn,scope,"PRESENT"); occurrence(key,conn,scope,"MISSING"); occurrence(key,conn,scope,"UNKNOWN");
        var detail=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        assertThat(detail.get("visibleLocationCount")).isEqualTo(3);
        assertThat(detail.get("locationStateCounts").toString()).contains("PRESENT=1","MISSING=1","UNKNOWN=1");
        assertThat(detail.toString()).doesNotContain("private/", "credential-secret", "fingerprint", "source_object_ref");
        assertThat(detail.get("items").toString()).contains("POST_ACTION_EVIDENCE_REQUIRED");
    }
    @Test void hiddenLocationDoesNotChangeVisibleCountVersionOrActivityTime() {
        long visibleConn=connection(),hiddenConn=connection(); grant(security,"SECURITY",visibleConn);
        long key=key("CONFIRMED","a2");
        occurrence(key,visibleConn,scope(visibleConn),"PRESENT");
        occurrence(key,hiddenConn,scope(hiddenConn),"PRESENT");
        var first=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        jdbc.update("UPDATE secret_occurrences SET last_seen_at=now()+interval '1 hour' WHERE connection_id=?",hiddenConn);
        var next=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        assertThat(next.get("visibleLocationCount")).isEqualTo(1);
        assertThat(next.get("detailVersion")).isEqualTo(first.get("detailVersion"));
        assertThat(next.get("credential")).isEqualTo(first.get("credential"));
        assertThat(next.get("restrictedCoverage")).isEqualTo(true);
    }
    @Test void humanScopeLabelsHelpLocateKeysWithoutCopyingProtectedPaths() {
        long conn=connection();grant(security,"SECURITY",conn);long scope=scope(conn),key=key("CONFIRMED","a3");
        occurrence(key,conn,scope,"PRESENT");
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias='주문 서비스 GitHub' WHERE scope_id=?",scope);
        var result=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        assertThat(result.get("items").toString()).contains("주문 서비스 GitHub · 위치 #").doesNotContain("private/","private-approved-ref");
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias='ghp_123456789012345678901234567890123456' WHERE scope_id=?",scope);
        result=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        assertThat(result.get("items").toString()).contains("위치 #").doesNotContain("ghp_123456");
    }
    @Test void authorizedLocationsRestoreSourceCoordinatesButOtherConnectionsStayHidden() {
        long conn=connection();grant(security,"SECURITY",conn);long scope=scope(conn),key=key("CONFIRMED","a4");
        jdbc.update("UPDATE secret_connection_scopes SET approved_ref='github://Logssey/test-find-key/main/fixtures/' WHERE scope_id=?",scope);
        occurrence(key,conn,scope,"PRESENT");
        jdbc.update("UPDATE secret_connection_scopes SET content_type='GITHUB_REPOSITORY_FILES' WHERE scope_id=?",scope);
        jdbc.update("UPDATE secret_occurrences SET source_object_ref='Logssey/test-find-key/fixtures/config/sample.env',location_key='L4',source_context_ref='github://Logssey/test-find-key/main/fixtures/',source_context_status='OBSERVED' WHERE scope_id=?",scope);
        var result=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        assertThat(result.get("items").toString()).contains("fixtures/config/sample.env","branch=main","line=L4");
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",security);
        assertCode(ErrorCode.FORBIDDEN,()->service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null));
    }

    @Test void operationsAndAdminDoNotGainCredentialReadRights() {
        long conn=connection(); grant(operations,"OPERATIONS",conn);
        assertCode(ErrorCode.FORBIDDEN,()->inventory("operations",filter("ALL"),null));
        assertCode(ErrorCode.FORBIDDEN,()->inventory("hidden",filter("ALL"),null));
    }
    @Test void snapshotFreezesPagesAndRejectsChangedFiltersAndRevokedGrants() {
        long conn=connection(); grant(security,"SECURITY",conn); long scope=scope(conn);
        occurrence(key("CONFIRMED","b1"),conn,scope,"PRESENT");
        var first=inventory("security",filter("VALUE_FINDINGS"),null);
        String id=first.get("snapshotId").toString();
        occurrence(key("CONFIRMED","b2"),conn,scope,"PRESENT");
        assertThat(((Number)inventory("security",filter("VALUE_FINDINGS"),id).get("total")).longValue()).isEqualTo(1);
        assertThat(((Number)inventory("security",filter("VALUE_FINDINGS"),null).get("total")).longValue()).isEqualTo(2);
        assertCode(ErrorCode.CONFLICT,()->inventory("security",filter("METADATA"),id));
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",security);
        assertCode(ErrorCode.FORBIDDEN,()->inventory("security",filter("VALUE_FINDINGS"),id));
    }
    @Test void metadataIsNotAValueFindingOrExposureDecisionQueue() {
        long conn=connection(); grant(security,"SECURITY",conn); long scope=scope(conn);
        occurrence(key("CONFIRMED","c1"),conn,scope,"PRESENT");
        occurrence(key("METADATA_ONLY","c2"),conn,scope,"PRESENT");
        assertThat(((Number)inventory("security",filter("VALUE_FINDINGS"),null).get("total")).longValue()).isEqualTo(1);
        var meta=inventory("security",filter("METADATA"),null);
        assertThat(((Number)meta.get("total")).longValue()).isEqualTo(1);
        assertThat(meta.get("items").toString()).contains("ACCESS_KEY_METADATA","UNCHECKED","INVENTORY");
    }
    @Test void onlyFiveActiveSnapshotsAreRetainedPerUser() {
        long conn=connection(); grant(security,"SECURITY",conn);
        var first=inventory("security",filter("ALL"),null);
        jdbc.update("UPDATE secret_query_snapshots SET created_at=clock_timestamp()-interval '1 minute' WHERE snapshot_id=?::uuid",first.get("snapshotId").toString());
        for(int i=0;i<5;i++) inventory("security",filter("ALL"),null);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots WHERE owner_user_id=?",Long.class,security))
            .isEqualTo(5);
        assertCode(ErrorCode.CONFLICT,()->inventory("security",filter("ALL"),first.get("snapshotId").toString()));
    }
    @Test void explicitOccurrenceInvalidationDoesNotWaitForWallClocksToAgree() {
        long conn=connection();grant(security,"SECURITY",conn);long key=key("CONFIRMED","a7");
        occurrence(key,conn,scope(conn),"PRESENT");
        long location=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE credential_set_id=?",Long.class,key);
        var first=inventory("security",filter("ALL"),null);String id=first.get("snapshotId").toString();
        jdbc.update("UPDATE secret_query_snapshots SET created_at=clock_timestamp()+interval '1 minute' WHERE snapshot_id=?::uuid",id);
        new SecretReadSnapshots(jdbc,JsonMapper.builder().build()).invalidateOccurrence(location);
        assertCode(ErrorCode.CONFLICT,()->inventory("security",filter("ALL"),id));
    }
    @Test void absentAndUnauthorizedKeysHaveTheSamePublicFailure() {
        long conn=connection(); grant(security,"SECURITY",conn);
        long other=connection(); long key=key("CONFIRMED","e1"); occurrence(key,other,scope(other),"PRESENT");
        assertCode(ErrorCode.NOT_FOUND,()->service.detail("security",key,"PRODUCTION"));
        assertCode(ErrorCode.NOT_FOUND,()->service.detail("security",99999,"PRODUCTION"));
    }
    @Test void filteringAnAuthorizedKeysLocationsToZeroReturnsAnEmptyPage() {
        long conn=connection(); grant(security,"SECURITY",conn); long key=key("CONFIRMED","f1");
        occurrence(key,conn,scope(conn),"PRESENT");
        var filters=new SecretInventoryFilters("PRODUCTION","AWS","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
        var result=service.locations("security",key,filters,0,20,"ALL","ALL","ALL",null);
        assertThat(result.get("total")).isEqualTo(0);
        assertThat(result.get("items")).isEqualTo(List.of());
        assertThat(((Map<?,?>)result.get("credential")).get("id")).isEqualTo(key);
    }
    @Test void severityFilterUsesTheHighestAuthorizedAssessment() {
        long conn=connection(),other=connection();grant(security,"SECURITY",conn);
        long key=key("CONFIRMED","f2");occurrence(key,conn,scope(conn),"PRESENT");
        occurrence(key,other,scope(other),"PRESENT");
        long visible=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE connection_id=?",Long.class,conn);
        long hiddenId=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE connection_id=?",Long.class,other);
        var risk=org.mockito.Mockito.mock(com.logssey.secret.risk.SecretRiskQueryService.class);
        org.springframework.test.util.ReflectionTestUtils.setField(service,"riskQueries",risk);
        org.mockito.Mockito.when(risk.occurrenceRisks(org.mockito.ArgumentMatchers.eq(security),org.mockito.ArgumentMatchers.anyCollection()))
            .thenReturn(Map.of(visible,risk("HIGH",1),hiddenId,risk("CRITICAL",1)));
        var high=new SecretInventoryFilters("PRODUCTION","ALL","ALL","ALL","ALL","ALL","ALL","ALL","HIGH");
        var result=inventory("security",high,null);
        assertThat(result.get("total")).isEqualTo(1L);
        assertThat(result.get("items").toString()).contains("severity=HIGH").doesNotContain("CRITICAL");
        org.mockito.Mockito.verify(risk).occurrenceRisks(security,List.of(visible));
    }
    @Test void riskUpdatesDoNotRewriteAnExistingInventorySnapshot() {
        long conn=connection();grant(security,"SECURITY",conn);long key=key("CONFIRMED","f3");
        occurrence(key,conn,scope(conn),"PRESENT");
        long id=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE credential_set_id=?",Long.class,key);
        var risk=org.mockito.Mockito.mock(com.logssey.secret.risk.SecretRiskQueryService.class);
        org.springframework.test.util.ReflectionTestUtils.setField(service,"riskQueries",risk);
        org.mockito.Mockito.when(risk.occurrenceRisks(org.mockito.ArgumentMatchers.eq(security),org.mockito.ArgumentMatchers.anyCollection()))
            .thenReturn(Map.of(id,risk("HIGH",1)));
        var first=inventory("security",filter("ALL"),null);
        org.mockito.Mockito.when(risk.occurrenceRisks(org.mockito.ArgumentMatchers.eq(security),org.mockito.ArgumentMatchers.anyCollection()))
            .thenReturn(Map.of(id,risk("CRITICAL",2)));
        assertThat(inventory("security",filter("ALL"),first.get("snapshotId").toString()).get("items").toString()).contains("severity=HIGH");
        assertThat(inventory("security",filter("ALL"),null).get("items").toString()).contains("severity=CRITICAL");
    }
    @Test void aChangedRiskRevisionInvalidatesAnOpenLocationContext() {
        long conn=connection();grant(security,"SECURITY",conn);long key=key("CONFIRMED","f4");
        occurrence(key,conn,scope(conn),"PRESENT");
        long id=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE credential_set_id=?",Long.class,key);
        var risk=org.mockito.Mockito.mock(com.logssey.secret.risk.SecretRiskQueryService.class);
        org.springframework.test.util.ReflectionTestUtils.setField(service,"riskQueries",risk);
        org.mockito.Mockito.when(risk.occurrenceRisks(org.mockito.ArgumentMatchers.eq(security),org.mockito.ArgumentMatchers.anyCollection()))
            .thenReturn(Map.of(id,risk("HIGH",1)));
        var first=service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",null);
        org.mockito.Mockito.when(risk.occurrenceRisks(org.mockito.ArgumentMatchers.eq(security),org.mockito.ArgumentMatchers.anyCollection()))
            .thenReturn(Map.of(id,risk("HIGH",2)));
        assertCode(ErrorCode.CONFLICT,()->service.locations("security",key,filter("ALL"),0,20,"ALL","ALL","ALL",first.get("detailVersion").toString()));
    }
    @Test void allOriginReadDeduplicatesKeyAndRetainsActualCaseOriginsWithoutHiddenFacts() {
        long key=key("CONFIRMED","ab21");
        for(String origin:List.of("PRODUCTION","TEST","UNCLASSIFIED")) {
            long c=connection(),s=scope(c);grant(security,"SECURITY",c);
            jdbc.update("UPDATE secret_connection_scopes SET response_origin=?,response_origin_set_by_user_id=CASE WHEN ?='UNCLASSIFIED' THEN NULL ELSE ? END,response_origin_set_at=CASE WHEN ?='UNCLASSIFIED' THEN NULL ELSE now() END WHERE scope_id=?",origin,origin,security,origin,s);
            occurrence(key,c,s,"PRESENT");long o=jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE scope_id=?",Long.class,s);
            long caseId=jdbc.queryForObject("INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin) VALUES(?,?,?,'APPROVED_EVIDENCE',?) RETURNING case_id",Long.class,key,o,security,origin);
            jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)",caseId,o,key);
        }
        long hiddenConnection=connection();occurrence(key,hiddenConnection,scope(hiddenConnection),"PRESENT");
        var all=new SecretInventoryFilters("ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL");
        var inventory=inventory("security",all,null);assertThat(inventory.get("total")).isEqualTo(1L);
        var item=service.detail("security",key,"ALL");
        assertThat(item).containsEntry("origin",null).containsEntry("readOrigin","ALL").containsEntry("currentCaseId",null).containsEntry("occurrenceCount",3);
        assertThat((List<?>)item.get("origins")).hasSize(3);
        assertThat(item.get("casesByOrigin").toString()).contains("origin=PRODUCTION","origin=TEST","origin=UNCLASSIFIED");
        assertThat(service.detail("security",key,"TEST")).containsEntry("origin","TEST").containsEntry("occurrenceCount",1);
        assertCode(ErrorCode.CONFLICT,()->inventory("security",filter("ALL"),inventory.get("snapshotId").toString()));
    }
    @Test void searchUsesVisibleLabelsBeforePaginationAndKeepsSnapshotBoundToQuery() {
        long c=connection(),s=scope(c);grant(security,"SECURITY",c);
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias='결제 서비스' WHERE scope_id=?",s);
        for(int i=0;i<3;i++)occurrence(key("CONFIRMED","ab3"+i),c,s,"PRESENT");
        long other=connection(),otherScope=scope(other);grant(security,"SECURITY",other);
        jdbc.update("UPDATE secret_connections SET provider='AWS' WHERE connection_id=?",other);
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias='AWS 설정' WHERE scope_id=?",otherScope);
        occurrence(jdbc.queryForObject("SELECT min(credential_set_id) FROM secret_credential_sets",Long.class),other,otherScope,"PRESENT");
        assertThat(inventory("security",new SecretInventoryFilters("ALL","AWS","ALL","ALL","ALL","ALL","ALL","ALL","ALL","결제"),null).get("total")).isEqualTo(0L);
        long hiddenConnection=connection(),hiddenScope=scope(hiddenConnection);
        jdbc.update("UPDATE secret_connection_scopes SET safe_display_alias='비공개 서비스' WHERE scope_id=?",hiddenScope);
        occurrence(key("CONFIRMED","ab40"),hiddenConnection,hiddenScope,"PRESENT");
        var search=new SecretInventoryFilters("ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL"," 결제 ");
        var first=tx.execute(t->service.inventory("security",search,0,2,null));
        assertThat(first.get("total")).isEqualTo(3L);assertThat((List<?>)first.get("items")).hasSize(2);
        var second=tx.execute(t->service.inventory("security",search,1,2,first.get("snapshotId").toString()));
        assertThat((List<?>)second.get("items")).hasSize(1);
        var hiddenSearch=new SecretInventoryFilters("ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","비공개");
        assertThat(inventory("security",hiddenSearch,null).get("total")).isEqualTo(0L);
        assertCode(ErrorCode.CONFLICT,()->inventory("security",hiddenSearch,first.get("snapshotId").toString()));
        assertThat(inventory("security",new SecretInventoryFilters("ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","credential-secret"),null).get("total")).isEqualTo(0L);
        long count=jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots",Long.class);
        assertCode(ErrorCode.INVALID_INPUT,()->inventory("security",new SecretInventoryFilters("ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL","ghp_"+"x".repeat(36)),null));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots",Long.class)).isEqualTo(count);
    }
    private Map<String,Object> risk(String grade,long revision) {
        return Map.of("latestAutomaticAssessment",Map.of("assessmentStatus","ASSESSED","severity",grade,"assessmentId",revision),
            "effectiveAssessment",Map.of("assessmentStatus","ASSESSED","severity",grade,"held",false,"assessmentId",revision),
            "evidenceRevision",revision);
    }
    private Map<String,Object> inventory(String login,SecretInventoryFilters f,String id) {
        return tx.execute(status->service.inventory(login,f,0,20,id));
    }
    private SecretInventoryFilters filter(String kind) {
        return new SecretInventoryFilters("PRODUCTION","ALL","ALL","ALL",kind,"ALL","ALL","ALL","ALL");
    }
    private long user(String name) { return jdbc.queryForObject("""
        INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES (?,'hash',?,'ADMIN') RETURNING user_id
        """,Long.class,name,name); }
    private long connection() { return jdbc.queryForObject("""
        INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
        VALUES ('GITHUB','private-display','private-auth','ACTIVE',1) RETURNING connection_id
        """,Long.class); }
    private void grant(long user,String role,long connection) { jdbc.update("""
        INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)
        VALUES (?,?,?,?,'MANUAL')
        """,user,role,connection,user); }
    private long scope(long connection) { return jdbc.queryForObject("""
        INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,
            response_origin,response_origin_set_by_user_id,response_origin_set_at)
        VALUES (?,'scope',1,'TEXT','private-approved-ref',true,'PRODUCTION',?,now()) RETURNING scope_id
        """,Long.class,connection,security); }
    private long key(String component,String fingerprint) { return jdbc.queryForObject("""
        INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,
            masked_label,first_seen_at,last_seen_at)
        VALUES ('AWS','AWS_ACCESS_KEY_PAIR',?,CASE WHEN ?='CONFIRMED' THEN decode(?,'hex') END,
            CASE WHEN ?='CONFIRMED' THEN 'test-v1' END,'AWS ••••1234',now(),now()) RETURNING credential_set_id
        """,Long.class,component,component,fingerprint,component); }
    private void occurrence(long key,long conn,long scope,String presence) { jdbc.update("""
        INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,
            environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
        VALUES (?,?,?,'private/credential-secret-'||nextval('secret_occurrences_occurrence_id_seq'),'L1',
            'UNKNOWN','UNKNOWN','UNKNOWN',?,now(),now())
        """,key,conn,scope,presence); }
    private void assertCode(ErrorCode code,Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(ApiException.class)
            .satisfies(e->assertThat(((ApiException)e).errorCode()).isEqualTo(code));
    }
}
