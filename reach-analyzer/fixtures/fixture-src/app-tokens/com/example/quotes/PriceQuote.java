package com.example.quotes;

import java.math.BigDecimal;

/** Deserialised, but only through a generic helper: no root sees it, only the class literal in QuoteConsumer names it. */
public record PriceQuote(String symbol, BigDecimal price) {
}
