package com.logssey.secret.run;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;

public record SecretRunRequest(
        @NotNull @Positive Long connectionId,
        @Pattern(regexp = "[A-Za-z0-9._:-]{1,120}") String idempotencyKey) {
}
