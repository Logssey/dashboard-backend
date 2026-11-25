package com.logssey.secret.response;

import java.time.OffsetDateTime;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import static org.assertj.core.api.Assertions.*;

class SecretLocationWorkflowIntegrationTest {
    static final PostgreSQLContainer DB=new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;static TransactionTemplate tx;static DataSourceTransactionManager tm;
    SecretLocationWorkflow service;SecretAccessService access;
    long security,alice,bob,conn1,conn2,occ1,occ2,caseId;
    @BeforeAll static void database(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);tx=new TransactionTemplate(tm);}
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void setup(){
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        security=user("security");alice=user("alice");bob=user("bob");conn1=connection();conn2=connection();
        grant(security,"SECURITY",conn1);grant(security,"SECURITY",conn2);grant(alice,"REMEDIATOR",conn1);grant(bob,"REMEDIATOR",conn2);
        long key=jdbc.queryForObject("""
            INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
            VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode('abcd','hex'),'test','AWS ••••1234',now(),now()) RETURNING credential_set_id
            """,Long.class);
        occ1=occurrence(key,conn1);occ2=occurrence(key,conn2);
        caseId=jdbc.queryForObject("""
            INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,assigned_user_id)
            VALUES(?,?,?,'APPROVED_EVIDENCE','PRODUCTION',?) RETURNING case_id
            """,Long.class,key,occ1,security,alice);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?),(?,?,?)",caseId,occ1,key,caseId,occ2,key);
        access=new SecretAccessService(jdbc);service=new SecretLocationWorkflow(jdbc,access,new SecretCommandExecutor(jdbc,tm),new SecretReadSnapshots(jdbc,JsonMapper.builder().build()));
    }
    @Test void ticketlessChecklistRecordsWhoConfirmedWithoutCompletingLocation() {
        assign(occ1,alice,0,0);
        var detail=service.detail(caseId,"alice");
        var item=((java.util.List<java.util.Map<String,Object>>)detail.get("checklist")).getFirst();
        long itemId=((Number)item.get("itemId")).longValue();
        tx.execute(s->service.checklist(caseId,itemId,new SecretLocationWorkflow.Checklist(true,"S2_V1",null,1L),"alice"));
        assertThat(jdbc.queryForObject("SELECT evidence_ref FROM secret_checklist_items WHERE item_id=?",String.class,itemId)).startsWith("CHANGE:RECORD-");
        assertThat(jdbc.queryForObject("SELECT actor_user_id FROM secret_internal_records",Long.class)).isEqualTo(alice);
        var reader=new com.logssey.secret.evidence.SecretInternalRecordController(jdbc,access,service,null,null);
        long record=jdbc.queryForObject("SELECT record_id FROM secret_internal_records",Long.class);
        assertThat(reader.detail(record,new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("alice","unused")).get("actorDisplayName")).isNotNull();
        code(ErrorCode.NOT_FOUND,()->reader.detail(record,new org.springframework.security.authentication.UsernamePasswordAuthenticationToken("bob","unused")));

        assertThat(jdbc.queryForObject("SELECT response_status FROM secret_case_occurrences WHERE occurrence_id=?",String.class,occ1)).isEqualTo("OPEN");
    }

    @Test void historyAllSearchUsesOnlyReadablePublicCaseAndLocationFacts() {
        jdbc.update("UPDATE secret_response_cases SET is_current=false,closed_at=now(),action_status='RESOLVED',resolved_at=now(),case_origin='UNCLASSIFIED' WHERE case_id=?",caseId);
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='UNCLASSIFIED',response_origin_set_by_user_id=NULL,response_origin_set_at=NULL,safe_display_alias='결제 서비스'");
        var history=service.list("security","ALL","history",null,null,null,0,20,"결제");
        assertThat(history.get("total")).isEqualTo(1);
        assertThat(history.get("items").toString()).contains("caseOrigin=UNCLASSIFIED");
        assertThat(service.list("security","PRODUCTION","history",null,null,null,0,20,"결제").get("total")).isEqualTo(0);
        assertThat(service.list("alice","ALL","history",null,null,null,0,20,"결제").get("total")).isEqualTo(0);
        assertThat(service.list("security","ALL","history",null,null,null,0,20,"private-path").get("total")).isEqualTo(0);
    }
    @Test void coordinatorAndConnectionGrantDoNotAssignLocations(){
        assertThat(access.canReadOccurrence(new SecretPrincipal(alice),occ1)).isFalse();
        code(ErrorCode.NOT_FOUND,()->service.detail(caseId,"alice"));
        assign(occ1,alice,0,0);var detail=service.detail(caseId,"alice");
        assertThat(detail.get("visibleOccurrenceCount")).isEqualTo(1);
        assertThat(detail.toString()).doesNotContain("private-path","auth-ref");
        assertThat(detail.get("restrictedCoverage")).isEqualTo(true);
        code(ErrorCode.FORBIDDEN,()->service.action(caseId,action(occ2,"ROTATED",1,0,"other"),"alice"));
    }
    @Test
    void assignedLocationUsesApprovedFileCoordinatesWithoutExposingOtherCaseMembers() {
        coordinates(
                occ1,
                "github://Example/project/main/fixtures/",
                "Example/project/fixtures/config.env",
                "L4-7");
        coordinates(
                occ2,
                "github://Hidden/repository/main/private/",
                "Hidden/repository/private/other.env",
                "L19");
        code(ErrorCode.NOT_FOUND, () -> service.detail(caseId, "alice"));
        assign(occ1, alice, 0, 0);
        var detail = service.detail(caseId, "alice");
        var own = items(detail).getFirst();
        assertThat(own.get("safeLocationLabel")).isEqualTo("Example/project/fixtures/config.env");
        assertThat(source(own))
                .containsEntry("repository", "Example/project")
                .containsEntry("branch", "main")
                .containsEntry("path", "fixtures/config.env")
                .containsEntry("line", "L4-7")
                .containsEntry(
                        "sourceUrl", "https://github.com/Example/project/blob/main/fixtures/config.env#L4-L7");
        assertThat(items(detail)).hasSize(1);
        String serialized = JsonMapper.builder().build().writeValueAsString(detail);
        assertThat(serialized)
                .doesNotContain(
                        "Hidden/repository",
                        "other.env",
                        "github://",
                        "auth-ref",
                        "source_object_ref",
                        "approved_ref");
        assertThat(service.visibleLocations(caseId, new SecretPrincipal(alice)).getFirst())
                .doesNotContainKeys("source_object_ref", "approved_ref", "location_key");
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?", alice);
        code(ErrorCode.NOT_FOUND, () -> service.detail(caseId, "alice"));
    }

    @Test
    void caseCoordinatesRejectWrongRepositoryTraversalAndChangedApprovalPrefix() {
        String approved = "github://Example/project/main/fixtures/";
        for (String path :
                java.util.List.of(
                        "Other/project/fixtures/wrong.env",
                        "Example/project/outside/wrong.env",
                        "Example/project/fixtures/../wrong.env")) {
            coordinates(occ1, approved, path, "L1");
            var location = items(service.detail(caseId, "security")).getFirst();
            assertThat(source(location)).containsEntry("status", "UNAVAILABLE");
            assertThat(location.get("safeLocationLabel")).isEqualTo("위치 #" + occ1);
            assertThat(location.toString()).doesNotContain(path, "github://");
        }
        coordinates(occ1, approved, "Example/project/fixtures/config.env", "L1");
        assertThat(source(items(service.detail(caseId, "security")).getFirst()))
                .containsEntry("status", "AVAILABLE");
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                        + " approved_ref='github://Example/project/main/new-scope/' WHERE scope_id=(SELECT"
                        + " scope_id FROM secret_occurrences WHERE occurrence_id=?)",
                occ1);
        assertThat(source(items(service.detail(caseId, "security")).getFirst()))
                .containsEntry("status", "UNAVAILABLE");
    }

    @Test
    void credentialLikeFileNamesAreMaskedAndNeverBecomeNavigableLinks() {
        String credentialLike = "ghp_" + "a".repeat(36);
        coordinates(
                occ1,
                "github://Example/project/main/fixtures/",
                "Example/project/fixtures/" + credentialLike + ".env",
                "L1");
        var location = items(service.detail(caseId, "security")).getFirst();
        assertThat(source(location))
                .containsEntry("status", "AVAILABLE")
                .containsEntry("sourceUrl", null);
        assertThat(location.get("safeLocationLabel").toString())
                .contains("마스킹")
                .doesNotContain(credentialLike);
        assertThat(JsonMapper.builder().build().writeValueAsString(service.detail(caseId, "security")))
                .doesNotContain(credentialLike);
    }

    private void coordinates(long occurrence, String approved, String path, String line) {
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                        + " content_type='GITHUB_REPOSITORY_FILES',history_limit='CURRENT_COMMIT_ONLY',approved_ref=?"
                        + " WHERE scope_id=(SELECT scope_id FROM secret_occurrences WHERE occurrence_id=?)",
                approved,
                occurrence);
        jdbc.update(
                "UPDATE secret_occurrences SET source_object_ref=?,location_key=?,source_context_ref=?,source_context_status='OBSERVED' WHERE occurrence_id=?",
                path,
                line,
                approved,
                occurrence);
    }

    @SuppressWarnings("unchecked")
    private java.util.List<Map<String, Object>> items(Map<String, Object> detail) {
        return (java.util.List<Map<String, Object>>) detail.get("occurrences");
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> source(Map<String, Object> location) {
        return (Map<String, Object>) location.get("sourceDetails");
    }

    @Test void firstActionStartsWorkWithoutASecondReviewAndCompletionIsSeparate(){
        assign(occ1,alice,0,0);
        var req=action(occ1,"ROTATED",1,1,"first");var result=service.action(caseId,req,"alice");
        assertThat(result.status()).isEqualTo(SecretCommandResult.Status.IN_PROGRESS);
        assertThat(jdbc.queryForObject("SELECT response_status FROM secret_case_occurrences WHERE occurrence_id=?",String.class,occ1)).isEqualTo("IN_PROGRESS");
        assertThat(service.action(caseId,req,"alice")).isEqualTo(result);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_action_records",Long.class)).isEqualTo(1);
        var complete=new SecretLocationWorkflow.Completion(2L,2L,"complete");
        assertThat(service.complete(caseId,occ1,complete,"alice").status()).isEqualTo(SecretCommandResult.Status.IN_PROGRESS);
        assertThat(jdbc.queryForObject("SELECT actions_completed_at IS NOT NULL FROM secret_case_occurrences WHERE occurrence_id=?",Boolean.class,occ1)).isTrue();
        code(ErrorCode.CONFLICT,()->service.action(caseId,action(occ1,"REVOKED",3,3,"after"),"alice"));
    }
    @Test void reducedPermissionCannotSubstituteForRemovalOrRevocation(){
        assign(occ1,alice,0,0);service.action(caseId,action(occ1,"PERMISSION_REDUCED",1,1,"reduce"),"alice");
        code(ErrorCode.CONFLICT,()->service.complete(caseId,occ1,new SecretLocationWorkflow.Completion(2L,2L,"done"),"alice"));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_location_activities WHERE activity_type='ACTIONS_COMPLETED'",Long.class)).isZero();
    }
    @Test void staleOrDifferentRetryCannotDuplicateActionsAndRevocationBlocksReplay(){
        assign(occ1,alice,0,0);var req=action(occ1,"ROTATED",1,1,"stable");service.action(caseId,req,"alice");
        code(ErrorCode.CONFLICT,()->service.action(caseId,action(occ1,"REVOKED",1,1,"stable"),"alice"));
        code(ErrorCode.CONFLICT,()->service.action(caseId,action(occ1,"ROTATED",1,1,"stale"),"alice"));
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",alice);
        code(ErrorCode.FORBIDDEN,()->service.action(caseId,req,"alice"));
    }
    @Test void targetMustHaveTheLocationsGrantAndTeamMembership(){
        code(ErrorCode.INVALID_INPUT,()->assign(occ1,bob,0,0));
        code(ErrorCode.INVALID_INPUT,()->tx.execute(s->service.assign(caseId,occ1,new SecretLocationWorkflow.Assignment("backend",alice,"INITIAL_ASSIGNMENT",0L,0L),"security")));
        assertThat(jdbc.queryForObject("SELECT version FROM secret_response_cases WHERE case_id=?",Long.class,caseId)).isZero();
    }
    @Test void activitiesAndCountsOnlyIncludeAssignedLocations(){
        assign(occ1,alice,0,0);assign(occ2,bob,1,0);service.action(caseId,action(occ2,"REVOKED",2,1,"b"),"bob");
        assertThat(service.activities(caseId,"alice",0,20).get("total")).isEqualTo(1L);
        assertThat(service.list("alice","PRODUCTION","currentCases",null,null,null,0,20).get("total")).isEqualTo(1);
        code(ErrorCode.CONFLICT,()->service.rejectLegacy(caseId,"alice"));
    }
    @Test void checklistIsLocationBoundAndCannotCompleteActions(){
        assign(occ1,alice,0,0);assign(occ2,bob,1,0);
        long own=jdbc.queryForObject("SELECT min(item_id) FROM secret_checklist_items WHERE occurrence_id=?",Long.class,occ1);
        long other=jdbc.queryForObject("SELECT min(item_id) FROM secret_checklist_items WHERE occurrence_id=?",Long.class,occ2);
        code(ErrorCode.FORBIDDEN,()->tx.execute(s->service.checklist(caseId,other,new SecretLocationWorkflow.Checklist(true,"S2_V1","TICKET:SEC-1",2L),"alice")));
        tx.execute(s->service.checklist(caseId,own,new SecretLocationWorkflow.Checklist(true,"S2_V1","TICKET:SEC-1",2L),"alice"));
        assertThat(jdbc.queryForObject("SELECT response_status FROM secret_case_occurrences WHERE occurrence_id=?",String.class,occ1)).isEqualTo("OPEN");
        assertThat(((java.util.List<?>)service.detail(caseId,"alice").get("checklist"))).hasSize(4);
    }
    @Test void optedInCoordinatorInheritsOnlyUnassignedEligibleLocationsAndFutureLinks() {
        grant(alice,"REMEDIATOR",conn2);
        tx.execute(status->service.coordinator(caseId,new SecretLocationWorkflow.Coordinator(null,alice,"INITIAL_ASSIGNMENT",0L,true),"security"));
        assertThat(jdbc.queryForList("SELECT assigned_user_id FROM secret_case_occurrences WHERE case_id=?",Long.class,caseId)).containsOnly(alice);
        long key=jdbc.queryForObject("SELECT credential_set_id FROM secret_response_cases WHERE case_id=?",Long.class,caseId);
        long nextConnection=connection();grant(alice,"REMEDIATOR",nextConnection);
        long third=occurrence(key,nextConnection);
        // Use another line so the existing same-scope location remains independently addressable.
        jdbc.update("UPDATE secret_occurrences SET location_key='L9' WHERE occurrence_id=?",third);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)",caseId,third,key);
        assertThat(jdbc.queryForObject("SELECT assigned_user_id FROM secret_case_occurrences WHERE occurrence_id=?",Long.class,third)).isEqualTo(alice);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_location_activities WHERE occurrence_id=? AND activity_type='LOCATION_ASSIGNED'",Long.class,third)).isEqualTo(1);
    }
    @Test void selfAssignmentRequiresActualRemediatorGrantsAndPreservesOtherOwners() {
        code(ErrorCode.INVALID_INPUT,()->tx.execute(status->service.assignSelf(caseId,new SecretLocationWorkflow.SelfAssignment(0L,true),"security")));
        grant(security,"REMEDIATOR",conn1);grant(security,"REMEDIATOR",conn2);
        assign(occ2,bob,0,0);
        tx.execute(status->service.assignSelf(caseId,new SecretLocationWorkflow.SelfAssignment(1L,true),"security"));
        assertThat(jdbc.queryForObject("SELECT assigned_user_id FROM secret_case_occurrences WHERE occurrence_id=?",Long.class,occ1)).isEqualTo(security);
        assertThat(jdbc.queryForObject("SELECT assigned_user_id FROM secret_case_occurrences WHERE occurrence_id=?",Long.class,occ2)).isEqualTo(bob);
    }
    @Test void internalActionReferenceAndCompletionCommitTogetherAndReplayOnce() {
        assign(occ1,alice,0,0);
        var request=new SecretLocationWorkflow.Action("ROTATED",occ1,OffsetDateTime.now().minusMinutes(1),null,1L,1L,"internal-and-done",true);
        var result=service.action(caseId,request,"alice");
        assertThat(service.action(caseId,request,"alice")).isEqualTo(result);
        assertThat(jdbc.queryForObject("SELECT evidence_ref FROM secret_action_records",String.class)).matches("CHANGE:ACTION-[1-9][0-9]*");
        assertThat(jdbc.queryForObject("SELECT response_status FROM secret_case_occurrences WHERE occurrence_id=?",String.class,occ1)).isEqualTo("REVALIDATION_PENDING");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_location_activities WHERE activity_type IN ('ACTION_RECORDED','ACTIONS_COMPLETED')",Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT version FROM secret_response_cases WHERE case_id=?",Long.class,caseId)).isEqualTo(2);
    }
    private SecretLocationWorkflow.Action action(long occ,String type,long cv,long ov,String key){return new SecretLocationWorkflow.Action(type,occ,OffsetDateTime.now().minusMinutes(1),"CHANGE:SEC-12",cv,ov,key);}
    private void assign(long occ,long user,long cv,long ov){tx.execute(s->service.assign(caseId,occ,new SecretLocationWorkflow.Assignment(null,user,"INITIAL_ASSIGNMENT",cv,ov),"security"));}
    private long user(String name){return jdbc.queryForObject("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES(?,'hash',?,'ADMIN') RETURNING user_id",Long.class,name,name);}
    private long connection(){return jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','private','auth-ref','ACTIVE',1) RETURNING connection_id",Long.class);}
    private void grant(long user,String role,long conn){jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,?,?,?,'MANUAL')",user,role,conn,security);}
    private long occurrence(long key,long conn){long scope=jdbc.queryForObject("""
        INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at)
        VALUES(?,'scope',1,'TEXT','private',true,'PRODUCTION',?,now()) RETURNING scope_id
        """,Long.class,conn,security);return jdbc.queryForObject("""
        INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
        VALUES(?,?,?,'private-path','L1','UNKNOWN','ABNORMAL','UNKNOWN','PRESENT',now(),now()) RETURNING occurrence_id
        """,Long.class,key,conn,scope);}
    private void code(ErrorCode expected,Runnable run){assertThatThrownBy(run::run).isInstanceOf(ApiException.class).satisfies(e->assertThat(((ApiException)e).errorCode()).isEqualTo(expected));}
}
