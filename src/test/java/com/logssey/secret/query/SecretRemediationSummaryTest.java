package com.logssey.secret.query;
import java.util.*;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
class SecretRemediationSummaryTest {
 @Test void absenceRequiresComparableEvidenceAndApprovedStorageIsNotAnEradicationTarget(){
  var present=facts("requiredRemediation",true,"presence","PRESENT","currentCoverage",true,
    "lastMaterialActionAt","2026-10-20T01:00:00Z","lastSeenAt","2026-10-21T01:00:00Z");
  var missing=facts("requiredRemediation",true,"presence","MISSING","locationAbsenceCheck",Map.of("status","PASSED"));
  var oldMissing=facts("requiredRemediation",true,"presence","MISSING","currentCoverage",true);
  var failed=facts("requiredRemediation",true,"presence","PRESENT","currentCoverage",false);
  var allowed=facts("requiredRemediation",false,"approvedStorage",true,"presence","PRESENT");
  var metadata=facts("metadataOnly",true,"presence","PRESENT");
  var summary=SecretRemediationSummary.summarize(List.of(present,missing,oldMissing,failed,allowed,metadata),true);
  assertThat(summary).containsEntry("requiredLocationCount",4L).containsEntry("presentLocationCount",1L)
    .containsEntry("postActionMissingLocationCount",1L).containsEntry("unknownLocationCount",2L)
    .containsEntry("postActionRedetectedCount",1L).containsEntry("approvedStorageLocationCount",1L)
    .containsEntry("metadataLocationCount",1L).containsEntry("restrictedCoverage",true).containsEntry("riskReductionPercent",null);
 }
 @Test void oldPresenceDoesNotAssertRedetectionAndPriorityNeverTreatsUnknownAsLowSeverity(){
  var old=facts("presence","PRESENT","currentCoverage",true,"lastMaterialActionAt","2026-10-21T01:00:00Z","lastSeenAt","2026-10-20T01:00:00Z");
  assertThat(SecretRemediationSummary.redetected(old)).isFalse();
  assertThat(SecretRemediationSummary.priority(Map.of("taskGuidance",Map.of("priorityReasonCodes",List.of("POST_ACTION_REDETECTED")))))
    .isLessThan(SecretRemediationSummary.priority(Map.of("taskGuidance",Map.of("priorityReasonCodes",List.of("CONFIRMED_EXPOSURE")))));
 }
}
