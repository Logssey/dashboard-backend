package com.logssey.secret.query;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class SecretRiskReadModelTest {
    @Test void highestVisibleGradeAndUnknownCountRemainIndependent() {
        var result=SecretRiskReadModel.summarize(List.of(1L,2L,3L),Map.of(
                1L,risk("ASSESSED","HIGH",false),2L,risk("ASSESSED","CRITICAL",false),
                3L,risk("UNASSESSED",null,false)),false);
        assertThat(result).containsEntry("severity","CRITICAL").containsEntry("unassessedOccurrenceCount",1L);
    }
    @Test void latestUnknownDoesNotEraseAHeldConfirmedGrade() {
        var result=SecretRiskReadModel.summarize(List.of(1L),Map.of(1L,risk("UNASSESSED","CRITICAL",true)),false);
        assertThat(result).containsEntry("severity","CRITICAL").containsEntry("unassessedOccurrenceCount",1L)
                .containsEntry("heldOccurrenceCount",1L);
    }
    @Test void normalStorageAndMetadataAreNotLowRiskOrUnassessed() {
        assertThat(SecretRiskReadModel.summarize(List.of(1L),Map.of(1L,risk("NOT_APPLICABLE",null,false)),false))
                .containsEntry("assessmentStatus","NOT_APPLICABLE").containsEntry("severity",null);
        assertThat(SecretRiskReadModel.summarize(List.of(1L),Map.of(1L,risk("ASSESSED","CRITICAL",true)),true))
                .containsEntry("assessmentStatus","NOT_APPLICABLE").containsEntry("unassessedOccurrenceCount",0L);
    }
    @Test void nonmembersCannotInfluenceTheHighestGradeOrCounts() {
        var result=SecretRiskReadModel.summarize(List.of(1L,1L),Map.of(1L,risk("UNASSESSED",null,false),
                2L,risk("ASSESSED","CRITICAL",false)),false);
        assertThat(result).containsEntry("severity","UNASSESSED").containsEntry("unassessedOccurrenceCount",1L);
    }
    @Test void absentOrUnexpectedEvidenceCannotProduceALowGrade() {
        assertThat(SecretRiskReadModel.summarize(List.of(1L),Map.of(),false))
                .containsEntry("severity","UNASSESSED");
        assertThat(SecretRiskReadModel.summarize(List.of(1L),Map.of(1L,risk("UNASSESSED","invented",false)),false))
                .containsEntry("severity","UNASSESSED");
    }
    @Test void expiredEvidenceIsUnassessedWithoutChangingTheHistoricalAutomaticResult() {
        var stale=new LinkedHashMap<>(risk("ASSESSED","HIGH",true));stale.put("unassessed",true);
        assertThat(SecretRiskReadModel.summarize(List.of(1L),Map.of(1L,stale),false))
                .containsEntry("severity","HIGH").containsEntry("unassessedOccurrenceCount",1L)
                .containsEntry("heldOccurrenceCount",1L);
        stale.put("effectiveAssessment",Map.of());
        assertThat(SecretRiskReadModel.summarize(List.of(1L),Map.of(1L,stale),false))
                .containsEntry("severity","UNASSESSED").containsEntry("unassessedOccurrenceCount",1L);
    }
    @Test void metadataCorrectionDoesNotEraseAStoredHeldApplication() {
        var historical = new LinkedHashMap<>(risk("NOT_APPLICABLE", "HIGH", true));
        historical.put("effectiveAssessment", Map.of("severity", "HIGH", "held", true, "assessmentId", 42L));
        assertThat(SecretRiskReadModel.summarize(List.of(1L), Map.of(1L, historical), true))
                .containsEntry("severity", "HIGH").containsEntry("heldOccurrenceCount", 1L)
                .containsEntry("unassessedOccurrenceCount", 0L);
    }
    private static Map<String,Object> risk(String status,String grade,boolean held) {
        var automatic=new LinkedHashMap<String,Object>();automatic.put("assessmentStatus",status);
        automatic.put("severity","ASSESSED".equals(status)?grade:null);
        var effective=new LinkedHashMap<String,Object>();effective.put("severity",grade);effective.put("held",held);
        return Map.of("latestAutomaticAssessment",automatic,"effectiveAssessment",effective);
    }
}
