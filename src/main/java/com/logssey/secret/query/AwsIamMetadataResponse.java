package com.logssey.secret.query;

import java.time.OffsetDateTime;

/** A listed IAM key is metadata only; this is not a validity result. */
public record AwsIamMetadataResponse(
        String keyStatus,
        OffsetDateTime issuedAt,
        OffsetDateTime lastUsedAt,
        String lastUsedService,
        String lastUsedRegion,
        OffsetDateTime observedAt) { }
