package com.logssey.secret.query;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import static org.assertj.core.api.Assertions.*;

class SecretWorkbenchIntegrationTest {
    static final PostgreSQLContainer DB=new PostgreSQLContainer("postgres:18.6");static JdbcTemplate jdbc;static TransactionTemplate tx;static DataSourceTransactionManager tm;
    SecretWorkbenchService service;long security,operations,connection,scope;
    @BeforeAll static void db(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);tx=new TransactionTemplate(tm);tx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);}
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void setup(){jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");security=user("security");operations=user("operations");connection=connection();scope=scope(connection);
        grant(security,"SECURITY",connection);grant(operations,"OPERATIONS",connection);
        var access=new SecretAccessService(jdbc);var json=JsonMapper.builder().build();var snapshots=new SecretReadSnapshots(jdbc,json);
        var workflow=new SecretLocationWorkflow(jdbc,access,new SecretCommandExecutor(jdbc,tm),snapshots);
        service=new SecretWorkbenchService(jdbc,access,new SecretLocationRepository(jdbc),workflow,new SecretCoverageService(jdbc,access),snapshots,json);
    }
    @Test void cardsAndQueueUseTheSameFrozenCasesWithDifferentUnits(){
        caseFixture(connection,scope);var first=summary("security",filters(),null);String id=first.get("snapshotId").toString();
        assertThat(metric(first,"ongoingCases").get("value")).isEqualTo(1L);
        assertThat(metric(first,"coverageGapScopes").get("value")).isEqualTo(1L);
        assertThat(first.get("total")).isNull();assertThat(first.get("unit")).isEqualTo("Mixed");
        caseFixture(connection,scope);
        var queue=tx.execute(s->service.queue("security",filters(),"ACTION_REQUIRED","OPEN,IN_PROGRESS",0,20,id));
        assertThat(queue.get("total")).isEqualTo(1);assertThat(queue.get("unit")).isEqualTo("ResponseCase");
        assertThat(metric(summary("security",filters(),null),"ongoingCases").get("value")).isEqualTo(2L);
    }
    @Test void acceptedRiskStaysOutsideActionCardsAndItsDeadlineExpiresTheFrozenCounts(){
        caseFixture(connection,scope);long id=jdbc.queryForObject("SELECT max(case_id) FROM secret_response_cases",Long.class);
        var closure=org.mockito.Mockito.mock(com.logssey.secret.closure.SecretClosureService.class);
        var deadline=java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).plusMinutes(3);
        org.mockito.Mockito.when(closure.riskAcceptanceDeadline(id,"security")).thenReturn(deadline);
        var access=new SecretAccessService(jdbc);var json=JsonMapper.builder().build();var snapshots=new SecretReadSnapshots(jdbc,json);
        service=new SecretWorkbenchService(jdbc,access,new SecretLocationRepository(jdbc),
            new SecretLocationWorkflow(jdbc,access,new SecretCommandExecutor(jdbc,tm),snapshots),new SecretCoverageService(jdbc,access),snapshots,json,closure);
        var first=summary("security",filters(),null);String snapshot=first.get("snapshotId").toString();
        assertThat(metric(first,"ongoingCases").get("value")).isEqualTo(0L);
        assertThat(((Map<?,?>)((Map<?,?>)first.get("caseSummary")).get("actionCounts")).get("RISK_ACCEPTED")).isEqualTo(1L);
        assertThat((java.time.OffsetDateTime)first.get("expiresAt")).isEqualTo(deadline);
        assertThat(tx.execute(s->service.queue("security",filters(),"ACTION_REQUIRED",null,0,20,snapshot)).get("total")).isEqualTo(0);
        assertThat(tx.execute(s->service.queue("security",filters(),"CURRENT_CASES","RISK_ACCEPTED",0,20,snapshot)).get("total")).isEqualTo(1);
        jdbc.update("UPDATE secret_query_snapshots SET expires_at=created_at+interval '1 microsecond' WHERE snapshot_id=?",java.util.UUID.fromString(snapshot));
        code(ErrorCode.CONFLICT,()->summary("security",filters(),snapshot));
        org.mockito.Mockito.when(closure.riskAcceptanceDeadline(id,"security")).thenReturn(null);
        assertThat(metric(summary("security",filters(),null),"ongoingCases").get("value")).isEqualTo(1L);
    }
    @Test void aGrantForConnectionOperationsDoesNotExposeKeysOrCases(){
        caseFixture(connection,scope);var result=summary("operations",filters(),null);
        assertThat(metric(result,"ongoingCases").get("status")).isEqualTo("NOT_AUTHORIZED");
        assertThat(metric(result,"ongoingCases").get("value")).isNull();
        assertThat(metric(result,"coverageGapScopes").get("status")).isEqualTo("AVAILABLE");
        assertThat(result.toString()).doesNotContain("AWS ••••1234","private-path","auth-ref");
    }
    @Test void hiddenActivityCannotChangeFrozenVisibleFacts(){
        caseFixture(connection,scope);var first=summary("security",filters(),null);long hidden=connection();long hiddenScope=scope(hidden);caseFixture(hidden,hiddenScope);
        assertThat(summary("security",filters(),first.get("snapshotId").toString())).isEqualTo(first);
        assertThat(first.get("restrictedCoverage")).isEqualTo(true);
    }
    @Test void filterMismatchAndRevokedGrantRejectSnapshotReuse(){
        caseFixture(connection,scope);var first=summary("security",filters(),null);String id=first.get("snapshotId").toString();
        code(ErrorCode.CONFLICT,()->summary("security",new SecretWorkbenchService.Filters("TEST","ALL","ALL","ALL",null,null),id));
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",security);
        code(ErrorCode.FORBIDDEN,()->summary("security",filters(),id));
    }
    @Test void coverageMetricsDeclareInapplicableAssigneeAndProviderFilters(){
        var f=new SecretWorkbenchService.Filters("PRODUCTION","ALL","AWS","UNKNOWN",null,"ME");var result=summary("security",f,null);
        assertThat(metric(result,"coverageGapScopes").get("notApplicableFilters")).isEqualTo(List.of("provider","environment","assignee"));
        assertThat(metric(result,"coverageGapScopes").get("value")).isEqualTo(1L);
    }
    @Test void teamAssignmentsMatchMeButAreNotCountedAsUnassigned(){
        caseFixture(connection,scope);grant(security,"REMEDIATOR",connection);
        jdbc.update("INSERT INTO secret_team_memberships(user_id,team_name,added_by_user_id) VALUES(?,'response-team',?)",security,security);
        jdbc.update("UPDATE secret_case_occurrences SET assigned_team='response-team'");
        var mine=new SecretWorkbenchService.Filters("PRODUCTION","ALL","ALL","ALL",null,"ME");
        var unassigned=new SecretWorkbenchService.Filters("PRODUCTION","ALL","ALL","ALL",null,"UNASSIGNED");
        assertThat(metric(summary("security",mine,null),"ongoingCases").get("value")).isEqualTo(1L);
        assertThat(metric(summary("security",unassigned,null),"ongoingCases").get("value")).isEqualTo(0L);
        assertThat(metric(summary("security",mine,null),"needsDecisionLocations").get("notApplicableFilters")).isEqualTo(List.of("assignee"));
    }
    @Test void aRemediatorsSnapshotIgnoresHiddenScopesButTracksItsOwnRevision(){
        caseFixture(connection,scope);long person=user("remediator");grant(person,"REMEDIATOR",connection);
        jdbc.update("UPDATE secret_case_occurrences SET assigned_user_id=?",person);
        long hidden=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled) VALUES(?,'hidden',1,'TEXT','private',true) RETURNING scope_id",Long.class,connection);
        var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().build());String first=snapshots.authorizationRevision(person);
        jdbc.update("UPDATE secret_connection_scopes SET response_origin_version=response_origin_version+1,enabled=false WHERE scope_id=?",hidden);
        assertThat(snapshots.authorizationRevision(person)).isEqualTo(first);
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=?",scope);
        assertThat(snapshots.authorizationRevision(person)).isNotEqualTo(first);
    }
    @Test void anEmptyVisibleScopeAliasInvalidatesItsFrozenQueueButNotHiddenScopes(){
        var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().build());
        var first=summary("operations",filters(),null);String id=first.get("snapshotId").toString();
        assertThat(metric(first,"unclassifiedScopes").get("value")).isEqualTo(1L);
        long hidden=scope(connection());snapshots.invalidateScope(hidden);
        assertThat(summary("operations",filters(),id)).isEqualTo(first);
        snapshots.invalidateScope(scope);
        code(ErrorCode.CONFLICT,()->summary("operations",filters(),id));
    }
    @Test void actionStagesAcceptSubsetsAndRejectIgnoredOrDuplicateStages(){
        caseFixture(connection,scope);
        var result=tx.execute(s->service.queue("security",filters(),"ACTION_REQUIRED","OPEN,REVALIDATION_PENDING",0,20,null));
        assertThat(result.get("total")).isEqualTo(1);
        for(String invalid:List.of("OPEN,OPEN","OPEN,","RESOLVED"))
            code(ErrorCode.INVALID_INPUT,()->tx.execute(s->service.queue("security",filters(),"ACTION_REQUIRED",invalid,0,20,null)));
        code(ErrorCode.INVALID_INPUT,()->tx.execute(s->service.queue("security",filters(),"NEEDS_DECISION","OPEN",0,20,null)));
    }
    @Test void crossOriginAlertsApplyTheOtherFiltersOnTheSameAuthorizedLocation(){
        long other=connection(),otherScope=scope(other);grant(security,"SECURITY",other);caseFixture(other,otherScope);
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='TEST' WHERE scope_id=?",otherScope);
        jdbc.update("UPDATE secret_response_cases SET case_origin='TEST'");
        long c=jdbc.queryForObject("SELECT max(case_id) FROM secret_response_cases",Long.class);
        long key=jdbc.queryForObject("SELECT credential_set_id FROM secret_response_cases WHERE case_id=?",Long.class,c);
        long occurrence=jdbc.queryForObject("SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id=?",Long.class,c);
        long alert=jdbc.queryForObject("INSERT INTO secret_cross_environment_alerts(credential_set_id,status,test_case_id,first_observed_at,last_observed_at) VALUES(?,'SUSPECTED_REAL',?,now(),now()) RETURNING alert_id",Long.class,key,c);
        jdbc.update("INSERT INTO secret_cross_environment_alert_locations(alert_id,occurrence_id,last_observed_at) VALUES(?,?,now())",alert,occurrence);
        for(var f:List.of(new SecretWorkbenchService.Filters("PRODUCTION","ALL","ALL","ALL",connection,null),
                new SecretWorkbenchService.Filters("PRODUCTION","AWS","ALL","ALL",other,null),
                new SecretWorkbenchService.Filters("PRODUCTION","ALL","GITHUB","ALL",other,null),
                new SecretWorkbenchService.Filters("PRODUCTION","ALL","ALL","PROD",other,null)))
            assertThat(((Map<?,?>)summary("security",f,null).get("crossEnvironmentAlerts")).get("value")).isEqualTo(0L);
        assertThat(((Map<?,?>)summary("security",new SecretWorkbenchService.Filters("PRODUCTION","GITHUB","AWS","UNKNOWN",other,null),null).get("crossEnvironmentAlerts")).get("value")).isEqualTo(1L);
    }
    private Map<String,Object> summary(String login,SecretWorkbenchService.Filters f,String id){return tx.execute(s->service.summary(login,f,id));}
    @SuppressWarnings("unchecked") private Map<String,Object> metric(Map<String,Object> summary,String key){return ((List<Map<String,Object>>)summary.get("metrics")).stream().filter(m->m.get("key").equals(key)).findFirst().orElseThrow();}
    private SecretWorkbenchService.Filters filters(){return new SecretWorkbenchService.Filters("PRODUCTION","ALL","ALL","ALL",null,null);}
    private long user(String login){return jdbc.queryForObject("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES(?,'hash',?,'ADMIN') RETURNING user_id",Long.class,login,login);}
    private long connection(){return jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','private','auth-ref','ACTIVE',1) RETURNING connection_id",Long.class);}
    private long scope(long conn){return jdbc.queryForObject("""
        INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at)
        VALUES(?,'scope',1,'TEXT','private-path',true,'PRODUCTION',?,now()) RETURNING scope_id
        """,Long.class,conn,security);}
    private void grant(long user,String role,long conn){jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,?,?,?,'MANUAL')",user,role,conn,security);}
    private void caseFixture(long conn,long scope){long key=jdbc.queryForObject("""
        INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
        VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(md5(random()::text),'hex'),'test','AWS ••••1234',now(),now()) RETURNING credential_set_id
        """,Long.class);long occ=jdbc.queryForObject("""
        INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
        VALUES(?,?,?,'private-path','L1','UNKNOWN','ABNORMAL','UNKNOWN','PRESENT',now(),now()) RETURNING occurrence_id
        """,Long.class,key,conn,scope);long c=jdbc.queryForObject("INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin) VALUES(?,?,?,'APPROVED_EVIDENCE','PRODUCTION') RETURNING case_id",Long.class,key,occ,security);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)",c,occ,key);}
    private void code(ErrorCode expected,Runnable run){assertThatThrownBy(run::run).isInstanceOf(ApiException.class).satisfies(e->assertThat(((ApiException)e).errorCode()).isEqualTo(expected));}
}
