package com.reused.product;

import java.math.BigDecimal;

/** Response only: Jackson serialises it, it is never deserialised from a request. */
public record ProductResponse(Long id, String title, BigDecimal price) {
}
