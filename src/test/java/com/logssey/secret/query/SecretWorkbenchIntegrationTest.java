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
