package com.logssey.secret.query;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import com.logssey.secret.testing.SecretTestPostgres;
import tools.jackson.databind.json.JsonMapper;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import static org.assertj.core.api.Assertions.*;

class SecretWorkbenchIntegrationTest {
    static final SecretTestPostgres DB=new SecretTestPostgres();static JdbcTemplate jdbc;static TransactionTemplate tx;static DataSourceTransactionManager tm;
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
    @Test void everyMatrixCellMatchesItsFrozenQueueAndUnassessedNeverBecomesLow(){
        for(int i=0;i<3;i++)caseFixture(connection,scope);
        var first=summary("security",filters(),null);String snapshot=first.get("snapshotId").toString();
        var cases=block(first.get("caseSummary"));var matrix=block(cases.get("severityValidityMatrix"));
        assertThat(matrix).containsEntry("status","AVAILABLE").containsEntry("unit","ResponseCase").containsEntry("total",3);
        assertThat(items(matrix.get("cells"))).hasSize(24);
        assertThat(block(cases.get("severityCounts"))).containsEntry("UNASSESSED",3L).containsEntry("LOW",0L);
        long sum=0;
        for(var cell:items(matrix.get("cells"))) {
            String grade=(String)cell.get("severity"),validity=(String)cell.get("validity");
            var queue=tx.execute(s->service.queue("security",filters(),"CURRENT_CASES",null,0,20,snapshot,grade,validity));
            assertThat(((Number)cell.get("value")).longValue()).isEqualTo(((Number)queue.get("total")).longValue());
            sum+=((Number)cell.get("value")).longValue();
            assertThat(block(cell.get("queueFilter"))).containsEntry("snapshotId",snapshot).containsEntry("bucket","CURRENT_CASES");
        }
        assertThat(sum).isEqualTo(3);
        caseFixture(connection,scope);
        var frozenMatrix=tx.execute(s->service.matrix("security",filters(),snapshot));
        var freshMatrix=tx.execute(s->service.matrix("security",filters(),null));
        assertThat(frozenMatrix).containsEntry("total",3);
        assertThat(freshMatrix).containsEntry("total",4);
    }
    @Test void matrixNeverIncludesHiddenConnectionsOtherOriginsOrWrongLocationFilterMatches(){
        caseFixture(connection,scope);
        long hidden=connection(),hiddenScope=scope(hidden);caseFixture(hidden,hiddenScope);
        long testConnection=connection(),testScope=scope(testConnection);grant(security,"SECURITY",testConnection);caseFixture(testConnection,testScope);
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='TEST' WHERE scope_id=?",testScope);
        jdbc.update("UPDATE secret_response_cases SET case_origin='TEST' WHERE opening_occurrence_id IN(SELECT occurrence_id FROM secret_occurrences WHERE scope_id=?)",testScope);
        var production=summary("security",filters(),null);
        assertThat(block(block(production.get("caseSummary")).get("severityValidityMatrix"))).containsEntry("total",1);
        var test=summary("security",new SecretWorkbenchService.Filters("TEST","ALL","ALL","ALL",null,null),null);
        assertThat(block(block(test.get("caseSummary")).get("severityValidityMatrix"))).containsEntry("total",1);
        var wrongSource=summary("security",new SecretWorkbenchService.Filters("PRODUCTION","AWS","ALL","ALL",null,null),null);
        assertThat(block(block(wrongSource.get("caseSummary")).get("severityValidityMatrix"))).containsEntry("total",0);
        var denied=block(block(summary("operations",filters(),null).get("caseSummary")).get("severityValidityMatrix"));
        assertThat(denied).containsEntry("status","NOT_AUTHORIZED").containsEntry("total",null).containsEntry("staleValidationCaseCount",null);
        assertThat(items(denied.get("cells"))).isEmpty();
        code(ErrorCode.FORBIDDEN,()->tx.execute(s->service.queue("operations",filters(),"CURRENT_CASES",null,0,20,null,"ALL","ALL")));
        code(ErrorCode.INVALID_INPUT,()->tx.execute(s->service.queue("security",filters(),"NEEDS_DECISION",null,0,20,null,"LOW","ALL")));
    }
    @Test void heldSeverityAndNotApplicableRemainDistinctFromUnassessedInDistributionAndQueue(){
        for(int i=0;i<3;i++)caseFixture(connection,scope);
        var ids=jdbc.queryForList("SELECT occurrence_id FROM secret_occurrences ORDER BY occurrence_id",Long.class);
        var risks=org.mockito.Mockito.mock(com.logssey.secret.risk.SecretRiskQueryService.class);
        org.mockito.Mockito.when(risks.occurrenceRisks(org.mockito.ArgumentMatchers.eq(security),org.mockito.ArgumentMatchers.anyList())).thenReturn(Map.of(
            ids.get(0),Map.of("latestAutomaticAssessment",Map.of("assessmentStatus","UNASSESSED"),"unassessed",true,
                "effectiveAssessment",Map.of("assessmentId",123L,"severity","HIGH","held",true)),
            ids.get(1),Map.of("latestAutomaticAssessment",Map.of("assessmentStatus","NOT_APPLICABLE"))));
        org.springframework.test.util.ReflectionTestUtils.setField(service,"riskQueries",risks);
        var first=summary("security",filters(),null);var cases=block(first.get("caseSummary"));
        assertThat(block(cases.get("severityCounts"))).containsEntry("HIGH",1L).containsEntry("UNASSESSED",1L).containsEntry("LOW",0L);
        assertThat(cases).containsEntry("notApplicableCaseCount",1L);
        var held=tx.execute(s->service.queue("security",filters(),"CURRENT_CASES",null,0,20,first.get("snapshotId").toString(),"HIGH","UNCHECKED"));
        assertThat(held).containsEntry("total",1);
        assertThat(items(held.get("items")).getFirst()).containsEntry("heldOccurrenceCount",1).containsEntry("unassessedOccurrenceCount",1);
        var excluded=tx.execute(s->service.queue("security",filters(),"CURRENT_CASES",null,0,20,first.get("snapshotId").toString(),"NOT_APPLICABLE","UNCHECKED"));
        assertThat(excluded).containsEntry("total",1);
        assertThat(items(excluded.get("items")).getFirst()).containsEntry("severity",null).containsEntry("assessmentStatus","NOT_APPLICABLE");
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
    @Test
    void setupCountsSeparateSelectedOriginUnclassifiedAndPausedScopesWithinTheLiveAcl() {
        jdbc.update(
                "UPDATE secret_connection_scopes SET response_origin='TEST' WHERE scope_id=?", scope);
        long unclassifiedConnection = connection(), unclassified = scope(unclassifiedConnection);
        grant(security, "SECURITY", unclassifiedConnection);
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                        + " response_origin='UNCLASSIFIED',response_origin_set_by_user_id=NULL,response_origin_set_at=NULL"
                        + " WHERE scope_id=?",
                unclassified);
        long pausedConnection = connection(), paused = scope(pausedConnection);
        grant(security, "SECURITY", pausedConnection);
        jdbc.update(
                "UPDATE secret_connections SET status='PAUSED' WHERE connection_id=?", pausedConnection);
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                        + " response_origin='UNCLASSIFIED',response_origin_set_by_user_id=NULL,response_origin_set_at=NULL"
                        + " WHERE scope_id=?",
                paused);
        scope(connection()); // Hidden setup must never contribute to any group.

        var production = summary("security", filters(), null);
        var setup = block(production.get("setupSummary"));
        assertThat(metric(production, "unclassifiedScopes").get("value")).isEqualTo(0L);
        assertThat(setup)
                .containsEntry("selectedOriginScopeCount", 0)
                .containsEntry("unclassifiedScopeCount", 1)
                .containsEntry("pausedScopeCount", 1);
        assertThat(items(setup.get("unclassifiedItems")))
                .extracting(row -> row.get("scopeId"))
                .containsExactly((int) unclassified);
        assertThat(items(setup.get("pausedItems")))
                .extracting(row -> row.get("scopeId"))
                .containsExactly((int) paused);
        assertThat(block(setup.get("reasonCounts")))
                .containsEntry("SOURCE_UNCLASSIFIED", 2L)
                .containsEntry("CONNECTION_PAUSED", 1L);
        assertThat(items(setup.get("pausedItems")).getFirst())
                .containsEntry("setupState", "PAUSED")
                .containsEntry("setupBlockedReasonCode", "CONNECTION_PAUSED");
        assertThat(block(items(setup.get("pausedItems")).getFirst().get("taskGuidance")))
                .containsEntry("canExecute", false);

        var testFilters = new SecretWorkbenchService.Filters("TEST", "ALL", "ALL", "ALL", null, null);
        var test = summary("security", testFilters, null);
        assertThat(metric(test, "unclassifiedScopes").get("value")).isEqualTo(1L);
        var queue =
                tx.execute(
                        status ->
                                service.queue(
                                        "security",
                                        testFilters,
                                        "UNCLASSIFIED",
                                        null,
                                        0,
                                        20,
                                        test.get("snapshotId").toString()));
        assertThat(queue.get("items")).isEqualTo(block(test.get("setupSummary")).get("items"));
        var restricted =
                summary(
                        "security",
                        new SecretWorkbenchService.Filters("TEST", "ALL", "ALL", "ALL", connection, null),
                        null);
        assertThat(block(restricted.get("setupSummary")))
                .containsEntry("unclassifiedScopeCount", 0)
                .containsEntry("pausedScopeCount", 0);
        var awsOnly =
                summary(
                        "security",
                        new SecretWorkbenchService.Filters("TEST", "AWS", "ALL", "ALL", null, null),
                        null);
        assertThat(block(awsOnly.get("setupSummary")))
                .containsEntry("selectedOriginScopeCount", 0)
                .containsEntry("unclassifiedScopeCount", 0)
                .containsEntry("pausedScopeCount", 0);
        new SecretReadSnapshots(jdbc, JsonMapper.builder().build()).invalidateScope(unclassified);
        code(
                ErrorCode.CONFLICT,
                () -> summary("security", filters(), production.get("snapshotId").toString()));
    }

    @Test
    void setupActionsMatchActualSecurityAuthorityAndSupportedActiveScope() {
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                        + " content_type='GITHUB_REPOSITORY_FILES',history_limit='CURRENT_COMMIT_ONLY',approved_ref='github://Logssey/test-find-key/main/fixtures/',response_origin='UNCLASSIFIED',response_origin_set_by_user_id=NULL,response_origin_set_at=NULL"
                        + " WHERE scope_id=?",
                scope);
        var coverage = new SecretCoverageService(jdbc, new SecretAccessService(jdbc));
        var securityScope =
                items(
                                coverage
                                        .scopes("security", connection, "ALL", "NEEDS_REVIEW", false, 0, 20)
                                        .get("items"))
                        .getFirst();
        assertThat(block(securityScope.get("capabilities")))
                .containsEntry("canClassifySource", true)
                .containsEntry("canConfigureStoragePolicy", true);
        assertThat(block(securityScope.get("taskGuidance"))).containsEntry("canExecute", true);
        var operationsScope =
                items(
                                coverage
                                        .scopes("operations", connection, "ALL", "NEEDS_REVIEW", false, 0, 20)
                                        .get("items"))
                        .getFirst();
        assertThat(block(operationsScope.get("capabilities")))
                .containsEntry("canEditAlias", true)
                .containsEntry("canClassifySource", false)
                .containsEntry("canConfigureStoragePolicy", false);
        assertThat(block(operationsScope.get("taskGuidance")))
                .containsEntry("canExecute", false)
                .containsEntry("blockedReasonCode", "ROLE_REQUIRED");
        long reviewer = user("reviewer");
        grant(reviewer, "SECURITY", connection);
        jdbc.update(
                "INSERT INTO"
                        + " secret_scope_classification_proposals(scope_id,expected_scope_version,scope_revision,scope_fingerprint,proposed_origin,reason_code,evidence_ref,proposed_by_user_id,status)"
                        + " SELECT"
                        + " scope_id,response_origin_version,revision,md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),'TEST','POLICY_PENDING','CHANGE:SEC-123',?,'PENDING_APPROVAL'"
                        + " FROM secret_connection_scopes WHERE scope_id=?",
                security,
                scope);
        var reviewable =
                items(
                                coverage
                                        .scopes("reviewer", connection, "ALL", "NEEDS_REVIEW", false, 0, 20)
                                        .get("items"))
                        .getFirst();
        assertThat(block(reviewable.get("capabilities")))
                .containsEntry("canReviewClassification", true);
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1 WHERE scope_id=?", scope);
        var stale =
                items(
                                coverage
                                        .scopes("reviewer", connection, "ALL", "NEEDS_REVIEW", false, 0, 20)
                                        .get("items"))
                        .getFirst();
        assertThat(block(stale.get("capabilities"))).containsEntry("canReviewClassification", false);
        assertThat(block(stale.get("taskGuidance"))).containsEntry("canExecute", false);
        jdbc.update("UPDATE secret_connections SET status='PAUSED' WHERE connection_id=?", connection);
        var paused =
                items(
                                coverage
                                        .scopes("security", connection, "ALL", "NEEDS_REVIEW", false, 0, 20)
                                        .get("items"))
                        .getFirst();
        assertThat(block(paused.get("capabilities")))
                .containsEntry("canClassifySource", false)
                .containsEntry("canConfigureStoragePolicy", false);
        jdbc.update("UPDATE secret_connections SET status='ACTIVE' WHERE connection_id=?", connection);
        jdbc.update(
                "UPDATE secret_connection_scopes SET approved_ref='unsupported' WHERE scope_id=?", scope);
        var unsupported =
                items(
                                coverage
                                        .scopes("security", connection, "ALL", "NEEDS_REVIEW", false, 0, 20)
                                        .get("items"))
                        .getFirst();
        assertThat(unsupported)
                .containsEntry("setupBlockedReasonCode", "SOURCE_CONFIGURATION_UNSUPPORTED");
        assertThat(block(unsupported.get("taskGuidance"))).containsEntry("canExecute", false);
    }

    @Test
    void responsePreviewsAreRealFrozenCaseRowsAndPreserveUnassessedCases() {
        for (int i = 0; i < 7; i++) caseFixture(connection, scope);
        jdbc.update("UPDATE secret_response_cases SET action_status='IN_PROGRESS' WHERE case_id=2");
        jdbc.update(
                "UPDATE secret_response_cases SET action_status='REVALIDATION_PENDING' WHERE case_id=7");
        jdbc.update(
                "UPDATE secret_case_occurrences SET response_status='REVALIDATION_PENDING' WHERE"
                        + " case_id=7");
        var result = summary("security", filters(), null);
        var previews = block(result.get("workPreviews"));
        var response = block(previews.get("response"));
        assertThat(response)
                .containsEntry("total", 6)
                .containsEntry("unit", "ResponseCase")
                .containsEntry("snapshotId", result.get("snapshotId"));
        assertThat(items(response.get("items")))
                .hasSize(5)
                .allSatisfy(row -> assertThat(row.get("severity")).isEqualTo("UNASSESSED"));
        assertThat(block(previews.get("revalidation"))).containsEntry("total", 1);
        var queue =
                tx.execute(
                        status ->
                                service.queue(
                                        "security",
                                        filters(),
                                        "ACTION_REQUIRED",
                                        "OPEN,IN_PROGRESS",
                                        0,
                                        5,
                                        result.get("snapshotId").toString()));
        assertThat(response.get("items")).isEqualTo(queue.get("items"));
        caseFixture(connection, scope);
        assertThat(summary("security", filters(), result.get("snapshotId").toString()))
                .isEqualTo(result);
        var operator =
                block(block(summary("operations", filters(), null).get("workPreviews")).get("response"));
        assertThat(operator).containsEntry("status", "NOT_AUTHORIZED").containsEntry("total", null);
        assertThat(items(operator.get("items"))).isEmpty();
    }

    @Test
    void collectionHealthRequiresCurrentRevisionAndOneActuallyCompleteRun() {
        long second =
                jdbc.queryForObject(
                        "INSERT INTO"
                                + " secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at)"
                                + " VALUES(?,'second',1,'TEXT','private-second',true,'PRODUCTION',?,now())"
                                + " RETURNING scope_id",
                        Long.class,
                        connection,
                        security);
        long firstRun = scan(connection, List.of(scope), true);
        long secondRun = scan(connection, List.of(second), true);
        var separated = block(summary("security", filters(), null).get("collectionHealth"));
        assertThat(block(separated.get("counts"))).containsEntry("success", 2L);
        assertThat(separated.get("lastScopeSuccess")).isNotNull();
        assertThat(separated.get("lastCompleteSuccess")).isNull();
        long incomplete = scan(connection, List.of(scope, second), false);
        jdbc.update(
                "UPDATE secret_run_scopes SET detection_stage_status='SUCCEEDED' WHERE run_id=? AND"
                        + " scope_id=?",
                incomplete,
                scope);
        var partial = block(summary("security", filters(), null).get("collectionHealth"));
        assertThat(partial.get("lastCompleteSuccess")).isNull();
        assertThat(block(partial.get("counts")))
                .containsEntry("partial", 1L)
                .containsEntry("success", 1L);
        assertThat(((Number) items(partial.get("items")).getFirst().get("scopeId")).longValue())
                .isEqualTo(second);
        jdbc.update(
                "UPDATE secret_run_scopes SET detection_stage_status=NULL WHERE run_id=?", incomplete);
        var unknown = block(summary("security", filters(), null).get("collectionHealth"));
        assertThat(block(unknown.get("counts")))
                .containsEntry("incomplete", 2L)
                .containsEntry("failed", 0L);
        jdbc.update(
                "UPDATE secret_run_scopes SET collection_status='SKIPPED' WHERE run_id=?", incomplete);
        assertThat(
                        block(
                                block(summary("security", filters(), null).get("collectionHealth")).get("counts")))
                .containsEntry("notRun", 2L)
                .containsEntry("failed", 0L);
        long complete = scan(connection, List.of(scope, second), true);
        var healthy = block(summary("security", filters(), null).get("collectionHealth"));
        assertThat(block(healthy.get("lastCompleteSuccess")).get("runId")).isEqualTo((int) complete);
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?", scope);
        var changed = block(summary("security", filters(), null).get("collectionHealth"));
        assertThat(changed.get("lastCompleteSuccess")).isNull();
        assertThat(block(changed.get("counts")))
                .containsEntry("notRun", 1L)
                .containsEntry("success", 1L);
        var changedScope =
                items(changed.get("items")).stream()
                        .filter(item -> ((Number) item.get("scopeId")).longValue() == scope)
                        .findFirst()
                        .orElseThrow();
        assertThat(block(changedScope.get("coverage")).get("lastSuccessfulScan")).isNull();
    }

    private long scan(long connection, List<Long> scopes, boolean complete) {
        long job =
                jdbc.queryForObject(
                        "INSERT INTO"
                                + " secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at)"
                                + " VALUES('FULL_SCAN',?,clock_timestamp(),now(),0,3,'SUCCEEDED',now()) RETURNING"
                                + " job_id",
                        Long.class,
                        connection);
        long run =
                jdbc.queryForObject(
                        "INSERT INTO"
                                + " secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at)"
                                + " VALUES(?,?,'MANUAL',1,now(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED',now())"
                                + " RETURNING run_id",
                        Long.class,
                        job,
                        connection);
        for (long id : scopes)
            jdbc.update(
                    "INSERT INTO"
                            + " secret_run_scopes(run_id,scope_id,collection_status,object_count,finished_at,detection_stage_status,validation_required,validation_stage_status)"
                            + " VALUES(?,?,'SUCCEEDED',0,clock_timestamp(),?,false,'SKIPPED')",
                    run,
                    id,
                    complete ? "SUCCEEDED" : "FAILED");
        return run;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> block(Object value) {
        return (Map<String, Object>) value;
    }

    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> items(Object value) {
        return (List<Map<String, Object>>) value;
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
