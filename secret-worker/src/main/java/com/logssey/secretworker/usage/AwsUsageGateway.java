package com.logssey.secretworker.usage;

import java.time.Instant;
import java.util.List;

/** Provider identifiers and JSON are short-lived values and never persistence contracts. */
public interface AwsUsageGateway extends AutoCloseable {
    String accountId();
    Principal principal(String userName);
    List<String> accessKeyIds(String userName);
    default List<String> userNames(){throw new AwsUsageFailure("KEY_IDENTIFIER_UNAVAILABLE",false,null);}
    Page lookup(String region, String accessKeyId, Instant start, Instant end, String nextToken);
    @Override default void close() { }
    record Principal(String arn,String principalId) { @Override public String toString(){return "Principal[REDACTED]";} }
    record Event(String id,String accessKeyId,String name,String source,Instant time,String rawJson) {
        @Override public String toString(){return "Event[REDACTED]";}
    }
    record Page(List<Event> events,String nextToken) {
        public Page { events=List.copyOf(events); }
        @Override public String toString(){return "Page[count="+events.size()+",hasNext="+(nextToken!=null)+"]";}
    }
}
