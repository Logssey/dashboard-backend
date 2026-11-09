package com.example.quotes;

/** Reads quotes from a feed. The class literal is the only thing that tells Jackson the type. */
public class QuoteConsumer {
    public PriceQuote handle(String json) throws Exception {
        return JsonSupport.read(json, PriceQuote.class);
    }
}
