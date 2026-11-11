package com.logssey.secret.query;

import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.logssey.secret.snapshot.SecretReadSnapshots;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class SecretWorkbenchRecoveryFactsTest {
  @Test
  void reviewUnionDeduplicatesOverlappingLocationsAndPrefersTheCaseCreationAction() {
    var snapshots = mock(SecretReadSnapshots.class);
    var now = OffsetDateTime.now();
    var header = new SecretReadSnapshots.Header(UUID.randomUUID(), "WORKBENCH", 1, now, now.plusMinutes(15), false);
    var link = facts("occurrenceId", 11, "credentialSetId", 1, "whyHereCode", "CASE_LINK_REQUIRED",
        "nextActionCode", "OPEN_REVIEW", "capabilities", Map.of("canReview", true));
    var duplicate = facts("occurrenceId", 11L, "credentialSetId", 1, "whyHereCode", "NEEDS_REVIEW",
        "nextActionCode", "OPEN_REVIEW", "capabilities", Map.of("canReview", true));
    var review = facts("occurrenceId", 12, "credentialSetId", 2, "whyHereCode", "NEEDS_REVIEW",
        "nextActionCode", "OPEN_REVIEW", "capabilities", Map.of("canReview", true));
    when(snapshots.page(header, "LinkOccurrence", 0, Integer.MAX_VALUE)).thenReturn(List.of(link));
    when(snapshots.page(header, "DecisionOccurrence", 0, Integer.MAX_VALUE)).thenReturn(List.of(duplicate, review));
    var result = new SecretWorkbenchRecoveryFacts(null, null, null, snapshots).reviewRows(header);
    assertThat(result).hasSize(2);
    assertThat(result.getFirst()).containsEntry("whyHereCode", "CASE_LINK_REQUIRED").containsEntry("nextActionCode", "LINK_CASE");
    assertThat(result.get(1)).containsEntry("nextActionCode", "REVIEW_EVIDENCE");
    assertThat(link).containsEntry("nextActionCode", "OPEN_REVIEW");
    assertThat(duplicate).containsEntry("nextActionCode", "OPEN_REVIEW");
  }
}
