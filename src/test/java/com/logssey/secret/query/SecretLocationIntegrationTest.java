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
        service=new SecretLocationService(new SecretLocationRepository(jdbc),
            new SecretReadSnapshots(jdbc,JsonMapper.builder().build()),new SecretAccessService(jdbc));
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
        for(int i=0;i<5;i++) inventory("security",filter("ALL"),null);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots WHERE owner_user_id=?",Long.class,security))
            .isEqualTo(5);
        assertCode(ErrorCode.NOT_FOUND,()->inventory("security",filter("ALL"),first.get("snapshotId").toString()));
    }
    @Test void absentAndUnauthorizedKeysHaveTheSamePublicFailure() {
        long conn=connection(); grant(security,"SECURITY",conn);
        long other=connection(); long key=key("CONFIRMED","e1"); occurrence(key,other,scope(other),"PRESENT");
        assertCode(ErrorCode.NOT_FOUND,()->service.detail("security",key,"PRODUCTION"));
        assertCode(ErrorCode.NOT_FOUND,()->service.detail("security",99999,"PRODUCTION"));
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
