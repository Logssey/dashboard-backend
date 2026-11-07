package com.logssey.secretworker.usage;

import com.logssey.secret.aws.SecretAwsSourceCredentials;
import java.time.*;
import java.util.*;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cloudtrail.CloudTrailClient;
import software.amazon.awssdk.services.cloudtrail.model.*;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.sts.StsClient;

/** Read-only management identity; discovered credentials are never used to query CloudTrail. */
public final class AwsSdkUsageGateway implements AwsUsageGateway {
    private final AwsCredentialsProvider credentials; private final StsClient sts;private final IamClient iam;
    private final Map<String,CloudTrailClient> clients=new HashMap<>();
    private static ClientOverrideConfiguration configuration(){return ClientOverrideConfiguration.builder().apiCallTimeout(Duration.ofSeconds(8)).apiCallAttemptTimeout(Duration.ofSeconds(8)).retryPolicy(RetryPolicy.none()).build();}
    public AwsSdkUsageGateway(SecretAwsSourceCredentials source){credentials=source::resolveCredentials;
        sts=StsClient.builder().credentialsProvider(credentials).region(Region.US_EAST_1).overrideConfiguration(configuration()).build();
        iam=IamClient.builder().credentialsProvider(credentials).region(Region.AWS_GLOBAL).overrideConfiguration(configuration()).build();}
    @Override public String accountId(){try{return sts.getCallerIdentity().account();}catch(RuntimeException e){throw safe(e);}}
    @Override public Principal principal(String name){try{var user=iam.getUser(r->r.userName(name)).user();return user==null?null:new Principal(user.arn(),user.userId());}catch(RuntimeException e){throw safe(e);}}
    @Override public List<String> accessKeyIds(String name){try{var response=iam.listAccessKeys(r->r.userName(name).maxItems(100));if(Boolean.TRUE.equals(response.isTruncated()))throw new AwsUsageFailure("KEY_IDENTIFIER_LIST_INCOMPLETE",false,null);return response.accessKeyMetadata().stream().map(k->k.accessKeyId()).toList();}catch(RuntimeException e){throw safe(e);}}
    @Override public List<String> userNames(){try{var response=iam.listUsers(r->r.maxItems(100));if(Boolean.TRUE.equals(response.isTruncated()))throw new AwsUsageFailure("KEY_IDENTIFIER_LIST_INCOMPLETE",false,null);return response.users().stream().map(u->u.userName()).toList();}catch(RuntimeException e){throw safe(e);}}
    @Override public Page lookup(String region,String id,Instant start,Instant end,String token){try{
        var client=clients.computeIfAbsent(region,r->CloudTrailClient.builder().credentialsProvider(credentials).region(Region.of(r)).overrideConfiguration(configuration()).build());
        var response=client.lookupEvents(LookupEventsRequest.builder().lookupAttributes(LookupAttribute.builder().attributeKey(LookupAttributeKey.ACCESS_KEY_ID).attributeValue(id).build()).startTime(start).endTime(end).maxResults(50).nextToken(token).build());
        return new Page(response.events().stream().map(e->new Event(e.eventId(),e.accessKeyId(),e.eventName(),e.eventSource(),e.eventTime(),e.cloudTrailEvent())).toList(),response.nextToken());
    }catch(RuntimeException e){throw safe(e);}}
    private static AwsUsageFailure safe(RuntimeException error){
        if(error instanceof AwsUsageFailure failure)return failure;
        if(error instanceof AwsServiceException e){
            String aws=e.awsErrorDetails()==null?"":Objects.toString(e.awsErrorDetails().errorCode(),"");
            if(e.statusCode()==401||e.statusCode()==403||Set.of("AccessDenied","AccessDeniedException","UnauthorizedOperation","OperationNotPermittedException").contains(aws))return new AwsUsageFailure("USAGE_ACCESS_DENIED",false,null);
            boolean rate=e.statusCode()==429||Set.of("Throttling","ThrottlingException","TooManyRequestsException").contains(aws);
            Instant retry=null;if(e.awsErrorDetails()!=null&&e.awsErrorDetails().sdkHttpResponse()!=null){var header=e.awsErrorDetails().sdkHttpResponse().firstMatchingHeader("Retry-After");if(header.isPresent())retry=retryAfter(header.get(),Instant.now());}
            return new AwsUsageFailure(rate?"USAGE_RATE_LIMITED":"USAGE_PROVIDER_UNAVAILABLE",rate||e.statusCode()>=500,retry);
        }
        return new AwsUsageFailure("USAGE_PROVIDER_UNAVAILABLE",true,null);
    }
    static Instant retryAfter(String header,Instant now){try{long seconds=Long.parseLong(header);return seconds>0?now.plusSeconds(Math.min(seconds,86400)):null;}catch(NumberFormatException notSeconds){try{Instant target=ZonedDateTime.parse(header,java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();return target.isAfter(now)?target.isAfter(now.plusSeconds(86400))?now.plusSeconds(86400):target:null;}catch(java.time.format.DateTimeParseException invalid){return null;}}}
    @Override public void close(){clients.values().forEach(CloudTrailClient::close);iam.close();sts.close();}
}
