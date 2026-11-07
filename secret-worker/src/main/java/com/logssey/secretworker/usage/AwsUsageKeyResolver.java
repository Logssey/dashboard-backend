package com.logssey.secretworker.usage;

import com.logssey.secretworker.aws.AwsMetadataIdentity;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import java.security.MessageDigest;
import java.util.*;

/** Raw identifiers only leave this resolver for the in-memory exact CloudTrail filter. */
public final class AwsUsageKeyResolver {
    private final SecretFindingNormalizer normalizer;private final AwsMetadataIdentity metadata;
    public AwsUsageKeyResolver(SecretFindingNormalizer normalizer,AwsMetadataIdentity metadata){this.normalizer=normalizer;this.metadata=metadata;}
    public String resolve(Map<String,Object> c,String account,AwsUsageGateway gateway,Runnable guard){
        if("METADATA_ONLY".equals(c.get("component_state"))){
            if(metadata==null||c.get("external_key_ref")==null)throw unavailable();
            guard.run();var users=gateway.userNames();String found=null;
            for(String user:users){guard.run();for(String id:gateway.accessKeyIds(user)){
                if(id!=null&&id.matches("AKIA[A-Z0-9]{16}")&&metadata.reference(account,id).equals(c.get("external_key_ref"))){if(found!=null&&!found.equals(id))throw unresolved();found=id;}
            }}
            if(found==null)throw unavailable();return found;
        }
        if(normalizer==null||!Objects.equals(normalizer.keyVersion(),c.get("fingerprint_key_version"))||!(c.get("aws_key_id_fingerprint") instanceof byte[] fingerprint))throw unavailable();
        if(c.get("identity_id")==null&&c.get("principal_type")==null)throw new AwsUsageFailure("FRESH_IDENTITY_VALIDATION_REQUIRED",false,null);
        if(!"IAM_USER".equals(c.get("principal_type"))||c.get("principal_ref")==null||c.get("principal_id")==null)throw unavailable();
        String arn=c.get("principal_ref").toString();if(!arn.startsWith("arn:aws:iam::"+account+":user/"))throw unresolved();
        String user=arn.substring(arn.lastIndexOf('/')+1);guard.run();var principal=gateway.principal(user);
        if(principal==null||!arn.equals(principal.arn())||!c.get("principal_id").equals(principal.principalId()))throw unresolved();
        guard.run();String found=null;for(String id:gateway.accessKeyIds(user)){
            if(id!=null&&id.matches("AKIA[A-Z0-9]{16}")&&MessageDigest.isEqual(fingerprint,normalizer.keyIdentifierFingerprint(id))){if(found!=null&&!found.equals(id))throw unresolved();found=id;}
        }
        if(found==null)throw unavailable();return found;
    }
    private static AwsUsageFailure unavailable(){return new AwsUsageFailure("KEY_IDENTIFIER_UNAVAILABLE",false,null);}
    private static AwsUsageFailure unresolved(){return new AwsUsageFailure("IDENTITY_BINDING_UNRESOLVED",false,null);}
}
