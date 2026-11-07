package com.logssey.secretworker.usage;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.*;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;
import tools.jackson.databind.json.JsonMapper;

/** Bounded management-event observation; neither a complete audit nor an abuse classifier. */
public final class AwsUsageObserver {
    public record Observation(String eventRef,Instant eventTime,String actionCode,String operationCode,String serviceCode,String actionResult,String actorAttribution){ }
    public record Result(String observationStatus,String coverageStatus,List<String> reasonCodes,int pages,int events,List<Observation> observations,Instant retryAt){
        public Result { reasonCodes=List.copyOf(reasonCodes);observations=List.copyOf(observations); }
    }
    @FunctionalInterface public interface Sleeper { void sleep(Duration duration); }
    private final JsonMapper json=JsonMapper.builder().build();private final Sleeper sleeper;private final int maxPages,maxEvents;
    private static final Set<String> ACTIONS=Set.of("GetCallerIdentity","AssumeRole","GetSessionToken","GetFederationToken","CreateAccessKey","UpdateAccessKey","DeleteAccessKey","ListAccessKeys","GetAccessKeyLastUsed","GetUser","ListUsers","AttachUserPolicy","DetachUserPolicy","PutUserPolicy","CreateUser","DeleteUser","CreateRole","DeleteRole","AttachRolePolicy","PutRolePolicy","ListBuckets","GetBucketPolicy","PutBucketPolicy","DeleteBucketPolicy","CreateBucket","DeleteBucket","DescribeInstances","RunInstances","TerminateInstances","AuthorizeSecurityGroupIngress","RevokeSecurityGroupIngress","GetSecretValue","PutSecretValue","DeleteSecret","DescribeSecret","GetParameter","GetParameters","PutParameter","DeleteParameter","Decrypt","Encrypt","GenerateDataKey","GetFunction","UpdateFunctionCode","LookupEvents","StopLogging","DeleteTrail");
    private static final Map<String,String> SERVICES=Map.ofEntries(Map.entry("sts.amazonaws.com","STS"),Map.entry("iam.amazonaws.com","IAM"),Map.entry("s3.amazonaws.com","S3"),Map.entry("ec2.amazonaws.com","EC2"),Map.entry("kms.amazonaws.com","KMS"),Map.entry("secretsmanager.amazonaws.com","SECRETS_MANAGER"),Map.entry("ssm.amazonaws.com","SSM"),Map.entry("lambda.amazonaws.com","LAMBDA"),Map.entry("cloudtrail.amazonaws.com","CLOUDTRAIL"));
    public AwsUsageObserver(){this(duration->{try{Thread.sleep(duration);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new AwsUsageFailure("USAGE_INTERRUPTED",false,null);}},100,5000);}
    public AwsUsageObserver(Sleeper sleeper,int maxPages,int maxEvents){if(maxPages<1||maxPages>100||maxEvents<1||maxEvents>5000)throw new IllegalArgumentException("USAGE_LIMIT_INVALID");this.sleeper=sleeper;this.maxPages=maxPages;this.maxEvents=maxEvents;}
    public AwsUsageObserver withBudget(int pages,int events){return new AwsUsageObserver(sleeper,Math.min(maxPages,pages),Math.min(maxEvents,events));}
    public Result observe(AwsUsageGateway gateway,String region,String keyId,Instant start,Instant end,Runnable guard,Runnable rateLimit){
        if(keyId==null||!keyId.matches("(?:AKIA|ASIA)[A-Z0-9]{16}")||start==null||end==null||!start.isBefore(end)||Duration.between(start,end).compareTo(Duration.ofDays(90))>0)throw new IllegalArgumentException("USAGE_QUERY_INVALID");
        var safe=new LinkedHashMap<String,Observation>();var reasons=new LinkedHashSet<String>();var tokens=new HashSet<String>();String token=null;int pages=0,events=0;
        while(true){
            AwsUsageGateway.Page page;
            try{page=lookup(gateway,region,keyId,start,end,token,guard,rateLimit);}
            catch(AwsUsageFailure failure){reasons.add(failure.code());return result(safe,reasons,pages,events,false,failure.retryAt());}
            pages++;if(page.events().size()>50){reasons.add("USAGE_RESPONSE_LIMIT");return result(safe,reasons,pages,events,false,null);}
            for(var event:page.events()){
                if(events>=maxEvents){reasons.add("USAGE_EVENT_LIMIT");return result(safe,reasons,pages,events,false,null);}events++;
                if(!keyId.equals(event.accessKeyId())||event.id()==null||!event.id().matches("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")||event.time()==null||event.time().isBefore(start)||event.time().isAfter(end)){reasons.add("USAGE_EVENT_BINDING_UNCONFIRMED");continue;}
                var observation=normalize(event,reasons);if(observation!=null)safe.putIfAbsent(observation.eventRef(),observation);
            }
            token=page.nextToken();if(token==null||token.isBlank())return result(safe,reasons,pages,events,reasons.isEmpty(),null);
            if(token.length()>8192||!tokens.add(token)){reasons.add("USAGE_PAGINATION_INVALID");return result(safe,reasons,pages,events,false,null);}
            if(pages>=maxPages){reasons.add("USAGE_PAGE_LIMIT");return result(safe,reasons,pages,events,false,null);}
        }
    }
    private AwsUsageGateway.Page lookup(AwsUsageGateway gateway,String region,String id,Instant start,Instant end,String token,Runnable guard,Runnable rate){
        for(int attempt=0;;attempt++){guard.run();rate.run();guard.run();try{return gateway.lookup(region,id,start,end,token);}catch(AwsUsageFailure failure){
            if(!failure.retryable()||attempt>=2)throw failure;
            if(failure.retryAt()!=null&&failure.retryAt().isAfter(Instant.now().plusSeconds(4)))throw failure;
            Duration pause=Duration.ofMillis((attempt==0?1000:3000)+ThreadLocalRandom.current().nextInt(101));
            if(failure.retryAt()!=null){Duration requested=Duration.between(Instant.now(),failure.retryAt());if(requested.compareTo(pause)>0)pause=requested;}
            sleeper.sleep(pause);
        }}
    }
    private Observation normalize(AwsUsageGateway.Event e,Set<String> reasons){
        String result="UNKNOWN";String raw=e.rawJson();
        if(raw!=null&&raw.length()<=262144)try{var value=json.readValue(raw,Map.class);
            if(value.get("userIdentity") instanceof Map<?,?> identity&&identity.get("accessKeyId")!=null&&!Objects.equals(identity.get("accessKeyId"),e.accessKeyId())){reasons.add("USAGE_EVENT_BINDING_UNCONFIRMED");return null;}
            if(Boolean.FALSE.equals(value.get("managementEvent"))||value.get("eventCategory")!=null&&!"Management".equals(value.get("eventCategory"))){reasons.add("USAGE_NON_MANAGEMENT_EVENT");return null;}
            if(value.get("eventVersion") instanceof String&&Objects.equals(value.get("eventName"),e.name()))result=value.get("errorCode") instanceof String code&&!code.isBlank()?"FAILURE":"SUCCESS";
            else reasons.add("USAGE_EVENT_DETAILS_UNAVAILABLE");
        }catch(RuntimeException ignored){reasons.add("USAGE_EVENT_DETAILS_UNAVAILABLE");}
        else reasons.add("USAGE_EVENT_DETAILS_UNAVAILABLE");
        String service=SERVICES.getOrDefault(Objects.toString(e.source(),""),"OTHER");
        String name=Objects.toString(e.name(),"");return new Observation(e.id(),e.time(),action(name),ACTIONS.contains(name)?name:"UNKNOWN",service.equals("LAMBDA")?"OTHER":service,result,"UNATTRIBUTED");
    }
    private Result result(Map<String,Observation> observations,Set<String> reasons,int pages,int events,boolean complete,Instant retry){
        String status=!observations.isEmpty()?"OBSERVED":complete?"NOT_OBSERVED_IN_SCOPE":"UNAVAILABLE";
        return new Result(status,complete?"COMPLETE":pages>0?"PARTIAL":"UNKNOWN",new ArrayList<>(reasons),pages,events,new ArrayList<>(observations.values()),retry);
    }
    private String action(String name){if(!ACTIONS.contains(name))return "UNKNOWN";if(Set.of("GetCallerIdentity","AssumeRole","GetSessionToken","GetFederationToken").contains(name))return "AUTHENTICATION";if(name.startsWith("Get")||name.startsWith("List")||name.startsWith("Describe")||name.equals("LookupEvents"))return "RESOURCE_READ";return "RESOURCE_CHANGE";}
}
