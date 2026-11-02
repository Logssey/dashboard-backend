package com.logssey.secret.query;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.logssey.overview.*;
import com.logssey.secret.access.*;
import com.logssey.secret.closure.SecretClosureService;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.risk.SecretRiskQueryService;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import com.logssey.secret.testing.SecretTestPostgres;
import java.time.OffsetDateTime;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.*;
import tools.jackson.databind.json.JsonMapper;

class SecretOverviewProjectionIntegrationTest {
  static final SecretTestPostgres DB=new SecretTestPostgres();
  static JdbcTemplate jdbc; static DataSourceTransactionManager tm;
  SecretOverviewProjection projection; OverviewService overview; SecretClosureService closure;
  long security,connection,scope;
  @BeforeAll static void start() {
    DB.start(); var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());
    Flyway.configure().dataSource(ds).load().migrate(); jdbc=new JdbcTemplate(ds); tm=new DataSourceTransactionManager(ds);
  }
  @AfterAll static void stop(){ DB.stop(); }
  @BeforeEach void setup() {
    jdbc.execute("TRUNCATE dashboard_users,secret_connections,detection_events,assets RESTART IDENTITY CASCADE");
    security=user("security"); user("outsider");
    connection=connection(); scope=scope(connection,"PRODUCTION"); grant(connection);
    var access=new SecretAccessService(jdbc);
    var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().build());
    var workflow=new SecretLocationWorkflow(jdbc,access,new SecretCommandExecutor(jdbc,tm),snapshots);
    var risk=mock(SecretRiskQueryService.class);
    when(risk.occurrenceRisks(anyLong(),anyCollection())).thenReturn(Map.of());
    closure=mock(SecretClosureService.class);
    projection=new SecretOverviewProjection(access,new SecretLocationRepository(jdbc),workflow,risk,closure);
    overview=new OverviewService(new OverviewQueryRepository(JdbcClient.create(jdbc.getDataSource())),projection);
  }
  @Test void onlyCurrentAuthorizedProductionCasesCountOnceAndUnknownStaysUnknown() {
    long visible=fixture(connection,scope,"PRODUCTION");
    long hidden=connection(); fixture(hidden,scope(hidden,"PRODUCTION"),"PRODUCTION");
    long test=connection(); grant(test); fixture(test,scope(test,"TEST"),"TEST");
    jdbc.update("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) SELECT credential_set_id,connection_id,scope_id,'private-path','L2','UNKNOWN','ABNORMAL','UNKNOWN','PRESENT',now(),now() FROM secret_occurrences WHERE occurrence_id=(SELECT opening_occurrence_id FROM secret_response_cases WHERE case_id=?)",visible);
    jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) SELECT ?,max(occurrence_id),credential_set_id FROM secret_occurrences WHERE credential_set_id=(SELECT credential_set_id FROM secret_response_cases WHERE case_id=?) GROUP BY credential_set_id",visible,visible);
    var result=projection.read("security","ALL");
    assertThat(result.cases()).hasSize(1); assertThat(result.unassessedCount()).isEqualTo(1);
    assertThat(result.cases().getFirst().environment()).isEqualTo("UNKNOWN");
    assertThat(result.cases().getFirst().severity()).isEqualTo("UNASSESSED");
    assertThat(projection.read("security","PROD").cases()).isEmpty();
    assertThat(projection.read("outsider","ALL")).satisfies(r->{assertThat(r.status()).isEqualTo("NOT_AUTHORIZED");assertThat(r.lastObservedAt()).isNull();});
    jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",security);
    assertThat(projection.read("security","ALL").cases()).isEmpty();
  }
  @Test void commonCountsLinksAndTrendComposeWithoutWritingLegacyEvents() {
    long id=fixture(connection,scope,"PRODUCTION");
    event("CONFIGURATION","HIGH");event("SECRETS","CRITICAL");
    var summary=overview.getSummary(EnvironmentFilter.ALL,"security");
    assertThat(summary.totalCount()).isEqualTo(2);assertThat(summary.securityScore()).isEqualTo(99);
    assertThat(summary.secretIntegration().unassessedCount()).isEqualTo(1);
    assertThat(summary.lastCollectedAt()).isNotNull();
    var priority=overview.getPriorityFindings(EnvironmentFilter.ALL,4,"security");
    assertThat(priority.unreviewedCount()).isEqualTo(2);
    var secret=priority.items().stream().filter(p->"SECRET_CASE".equals(p.sourceType())).findFirst().orElseThrow();
    assertThat(secret.eventId()).isNull();assertThat(secret.sourceId()).isEqualTo(id);
    assertThat(secret.detailPath()).isEqualTo("/secrets/cases/"+id+"?origin=PRODUCTION");
    assertThat(secret.environment()).isEqualTo("UNKNOWN");
    assertThat(overview.getRiskTrend(EnvironmentFilter.ALL,1,"security").days().getFirst()).satisfies(d->{assertThat(d.total()).isEqualTo(2);assertThat(d.high()).isEqualTo(1);assertThat(d.unassessed()).isEqualTo(1);});
    assertThat(jdbc.queryForObject("SELECT count(*) FROM detection_events",Long.class)).isEqualTo(2);
    assertThat(overview.getSummary(EnvironmentFilter.ALL,"outsider").secretIntegration()).satisfies(s->{assertThat(s.status()).isEqualTo("NOT_AUTHORIZED");assertThat(s.total()).isNull();});
  }
  @Test void acceptedRiskDoesNotAppearAsAnOpenActionAndEmptyTimestampIsNotServerStartup() {
    assertThat(overview.getSummary(EnvironmentFilter.ALL,"security").lastCollectedAt()).isNull();
    long id=fixture(connection,scope,"PRODUCTION");
    when(closure.riskAcceptanceDeadline(id,"security")).thenReturn(OffsetDateTime.now().plusHours(1));
    assertThat(overview.getSummary(EnvironmentFilter.ALL,"security").totalCount()).isEqualTo(1);
    assertThat(overview.getPriorityFindings(EnvironmentFilter.ALL,4,"security").items()).isEmpty();
    assertThat(overview.getSummary(EnvironmentFilter.ALL,"security").unreviewedCount()).isZero();
  }
  long user(String name){ return jdbc.queryForObject("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES(?,'hash',?,'ADMIN') RETURNING user_id",Long.class,name,name); }
  long connection(){ return jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','private','protected','ACTIVE',1) RETURNING connection_id",Long.class); }
  long scope(long conn,String origin){return jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at) VALUES(?,'scope',1,'TEXT','private-path',true,?,?,now()) RETURNING scope_id",Long.class,conn,origin,security);}
  void grant(long conn){jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,'SECURITY',?,?,'MANUAL')",security,conn,security);}
  long fixture(long conn,long scope,String origin){
    long key=jdbc.queryForObject("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at) VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(md5(random()::text),'hex'),'test','AWS ••••1234',now(),now()) RETURNING credential_set_id",Long.class);
    long occ=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(?,?,?,'private-path','L1','UNKNOWN','ABNORMAL','UNKNOWN','PRESENT',now(),now()) RETURNING occurrence_id",Long.class,key,conn,scope);
    long id=jdbc.queryForObject("INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin) VALUES(?,?,?,'APPROVED_EVIDENCE',?) RETURNING case_id",Long.class,key,occ,security,origin);
    jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)",id,occ,key); return id;
  }
  void event(String domain,String grade){jdbc.update("INSERT INTO detection_events(severity,title,environment,owner_team,detected_at,domain) VALUES(?,'safe event','PROD','ops',now(),?)",grade,domain);}
}
