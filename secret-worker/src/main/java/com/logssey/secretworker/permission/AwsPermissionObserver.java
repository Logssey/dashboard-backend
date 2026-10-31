package com.logssey.secretworker.permission;

import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secret.permission.core.SecretPermissionContext;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.*;
import software.amazon.awssdk.services.sts.StsClient;

/** Only an explicitly approved IAM metadata account and actually bound principal are queried. */
public class AwsPermissionObserver {
    public PermissionCandidate observe(Map<String,Object> identity,SecretAwsSourceCredentials source){
        return observe(identity,source,()->{});
    }
    public PermissionCandidate observe(Map<String,Object> identity,SecretAwsSourceCredentials source,Runnable guard){
        if(source==null)return PermissionCandidate.unavailable("COLLECTOR_NOT_CONFIGURED");
        long deadline=System.nanoTime()+Duration.ofSeconds(60).toNanos();
        Runnable boundedGuard=()->{if(System.nanoTime()>deadline)throw new ObservationDeadline();guard.run();};
        AwsCredentialsProvider borrowed=source::resolveCredentials;
        try(var sts=StsClient.builder().credentialsProvider(borrowed).region(Region.US_EAST_1).overrideConfiguration(c->c.apiCallTimeout(Duration.ofSeconds(8))).build();
            var iam=IamClient.builder().credentialsProvider(borrowed).region(Region.AWS_GLOBAL).overrideConfiguration(c->c.apiCallTimeout(Duration.ofSeconds(8))).build()){
            boundedGuard.run();if(!Objects.equals(sts.getCallerIdentity().account(),identity.get("account_ref")))return PermissionCandidate.unavailable("COLLECTOR_ACCOUNT_MISMATCH");
            IamClient guarded=(IamClient)java.lang.reflect.Proxy.newProxyInstance(IamClient.class.getClassLoader(),new Class<?>[]{IamClient.class},(proxy,method,args)->{
                if(!Set.of("close","serviceName","serviceClientConfiguration","toString","hashCode","equals").contains(method.getName()))boundedGuard.run();
                try{return method.invoke(iam,args);}catch(java.lang.reflect.InvocationTargetException error){throw error.getCause();}
            });
            return observeBound(identity,guarded);
        }catch(ObservationDeadline deadlineExceeded){return PermissionCandidate.unavailable("PERMISSION_TIME_BUDGET_EXHAUSTED");}
        catch(software.amazon.awssdk.awscore.exception.AwsServiceException error){return PermissionCandidate.unavailable(error.statusCode()==401||error.statusCode()==403?"PERMISSION_ACCESS_DENIED":error.statusCode()==429?"PERMISSION_RATE_LIMITED":"PERMISSION_PROVIDER_UNAVAILABLE");}
        catch(RuntimeException unavailable){return PermissionCandidate.unavailable("PERMISSION_PROVIDER_UNAVAILABLE");}
    }
    PermissionCandidate observeBound(Map<String,Object> identity,IamClient iam){
        String arn=identity.get("principal_ref").toString(),principal=identity.get("principal_id").toString();var docs=new ArrayList<String>();boolean complete=true;
        if("IAM_USER".equals(identity.get("principal_type"))){
            String name=arn.substring(arn.lastIndexOf('/')+1);var user=iam.getUser(r->r.userName(name)).user();
            if(user==null||!arn.equals(user.arn())||!principal.equals(user.userId()))return PermissionCandidate.unavailable("CREDENTIAL_IDENTITY_MISMATCH");
            var attached=iam.listAttachedUserPolicies(r->r.userName(name).maxItems(100));complete&=!Boolean.TRUE.equals(attached.isTruncated());
            for(var policy:attached.attachedPolicies()){if(docs.size()>=30){complete=false;break;}managed(iam,policy.policyArn(),docs);}
            var inline=iam.listUserPolicies(r->r.userName(name).maxItems(100));complete&=!Boolean.TRUE.equals(inline.isTruncated());
            for(String policy:inline.policyNames()){if(docs.size()>=30){complete=false;break;}add(iam.getUserPolicy(r->r.userName(name).policyName(policy)).policyDocument(),docs);}
            var groups=iam.listGroupsForUser(r->r.userName(name).maxItems(100));complete&=!Boolean.TRUE.equals(groups.isTruncated());int processed=0;
            for(var group:groups.groups()){if(++processed>20||docs.size()>=30){complete=false;break;}String g=group.groupName();var groupAttached=iam.listAttachedGroupPolicies(r->r.groupName(g).maxItems(100));complete&=!Boolean.TRUE.equals(groupAttached.isTruncated());
                for(var policy:groupAttached.attachedPolicies()){if(docs.size()>=30){complete=false;break;}managed(iam,policy.policyArn(),docs);}
                var groupInline=iam.listGroupPolicies(r->r.groupName(g).maxItems(100));complete&=!Boolean.TRUE.equals(groupInline.isTruncated());for(String policy:groupInline.policyNames()){if(docs.size()>=30){complete=false;break;}add(iam.getGroupPolicy(r->r.groupName(g).policyName(policy)).policyDocument(),docs);}
            }
            if(user.permissionsBoundary()!=null)complete=false;
        }else if("ASSUMED_ROLE".equals(identity.get("principal_type"))){
            String name=arn.substring(arn.indexOf(":assumed-role/")+14).split("/",2)[0];var role=iam.getRole(r->r.roleName(name)).role();
            if(role==null||!principal.split(":",2)[0].equals(role.roleId())||!role.arn().contains("::"+identity.get("account_ref")+":"))return PermissionCandidate.unavailable("CREDENTIAL_IDENTITY_MISMATCH");
            var attached=iam.listAttachedRolePolicies(r->r.roleName(name).maxItems(100));complete&=!Boolean.TRUE.equals(attached.isTruncated());for(var policy:attached.attachedPolicies()){if(docs.size()>=30){complete=false;break;}managed(iam,policy.policyArn(),docs);}
            var inline=iam.listRolePolicies(r->r.roleName(name).maxItems(100));complete&=!Boolean.TRUE.equals(inline.isTruncated());for(String policy:inline.policyNames()){if(docs.size()>=30){complete=false;break;}add(iam.getRolePolicy(r->r.roleName(name).policyName(policy)).policyDocument(),docs);}
            if(role.permissionsBoundary()!=null)complete=false;
        }else return PermissionCandidate.unsupported("PRINCIPAL_TYPE_MANUAL_REVIEW_REQUIRED");
        return new PermissionCapabilityNormalizer().aws(docs,complete,"ASSUMED_ROLE".equals(identity.get("principal_type")));
    }
    private void managed(IamClient iam,String arn,List<String> docs){var policy=iam.getPolicy(r->r.policyArn(arn)).policy();if(policy==null||policy.defaultVersionId()==null)throw new IllegalStateException("POLICY_VERSION_UNAVAILABLE");add(iam.getPolicyVersion(r->r.policyArn(arn).versionId(policy.defaultVersionId())).policyVersion().document(),docs);}
    private void add(String encoded,List<String> docs){if(encoded==null||encoded.length()>131072)throw new IllegalStateException("POLICY_DOCUMENT_LIMIT");String decoded=encoded.stripLeading().startsWith("{")?encoded:URLDecoder.decode(encoded,StandardCharsets.UTF_8);if(decoded.length()>65536)throw new IllegalStateException("POLICY_DOCUMENT_LIMIT");docs.add(decoded);}
    private static final class ObservationDeadline extends RuntimeException{}
}
