package com.logssey.secret.query;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.regex.Pattern;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

/** Authorized source coordinates only. Never returns file contents, auth refs or key identities. */
public final class SecretSourceDetails {
    private SecretSourceDetails() { }
    private static final Pattern CREDENTIAL = Pattern.compile("AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+|(?:secret_|ntn_)[A-Za-z0-9]{20,}|[A-Za-z0-9_+=-]{32,}");
    private static String safe(String value) {
        if(value==null || value.length()>700 || value.chars().anyMatch(c->c<32||c==127)||value.contains("\\")) return null;
        return CREDENTIAL.matcher(value).replaceAll("[마스킹]");
    }
    private static String decode(String value) { return URLDecoder.decode(value.replace("+","%2B"),StandardCharsets.UTF_8); }
    private static String encode(String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8).replace("+","%20"); }
    public static String scopeLabel(String provider,String approvedRef,long scopeId) {
        try {
            var uri=URI.create(approvedRef);
            if(uri.getRawUserInfo()!=null||uri.getPort()!=-1||uri.getRawQuery()!=null||uri.getRawFragment()!=null)return "검사 대상 #"+scopeId;
            var p=uri.getRawPath().split("/",-1);
            if("GITHUB".equals(provider)&&"github".equals(uri.getScheme())&&uri.getHost()!=null&&p.length>=5) {
                String label=safe(uri.getHost()+"/"+decode(p[1])+" · "+decode(p[2])+" · "+String.join("/",Arrays.stream(p).skip(3).map(SecretSourceDetails::decode).toList()));
                if(label!=null)return label;
            }
            if("AWS".equals(provider)&&"aws".equals(uri.getScheme())&&uri.getHost()!=null&&uri.getHost().matches("[0-9]{12}")&&p.length>=3) {
                String label=safe(String.join("/",Arrays.stream(p).skip(1).map(SecretSourceDetails::decode).toList()));
                if(label!=null)return label;
            }
        }catch(RuntimeException ignored) { }
        return "검사 대상 #"+scopeId;
    }
    public static Map<String,Object> describe(String provider,String approvedRef,String sourceRef,String lineRef) {
        var unavailable=facts("status","UNAVAILABLE","label","발견 위치 확인 필요","reasonCode","SOURCE_COORDINATES_UNAVAILABLE");
        try {
            var uri=URI.create(approvedRef);
            if(uri.getUserInfo()!=null||uri.getPort()!=-1||uri.getQuery()!=null||uri.getFragment()!=null) return unavailable;
            if("GITHUB".equals(provider)&&"github".equals(uri.getScheme())) {
                String[] parts=uri.getRawPath().split("/",-1);
                if(parts.length<5 || !parts[parts.length-1].isEmpty() || uri.getHost()==null) return unavailable;
                String owner=uri.getHost(),repo=decode(parts[1]),branch=decode(parts[2]);
                if(!owner.matches("[A-Za-z0-9-]{1,39}")||!repo.matches("[A-Za-z0-9_.-]{1,100}")||branch.isBlank())return unavailable;
                String prefix=String.join("/",Arrays.stream(parts).skip(3).limit(parts.length-4L).map(SecretSourceDetails::decode).toList())+"/";
                String root=owner+"/"+repo+"/";
                if(sourceRef==null||!sourceRef.startsWith(root))return unavailable;
                String path=sourceRef.substring(root.length());
                if(!path.startsWith(prefix)||Arrays.stream(path.split("/",-1)).anyMatch(p->p.isBlank()||p.equals(".")||p.equals("..")))return unavailable;
                String safePath=safe(path),safeBranch=safe(branch),safeRepo=safe(owner+"/"+repo);
                if(safePath==null||safeBranch==null||safeRepo==null)return unavailable;
                String lines=lineRef!=null&&lineRef.matches("L[1-9][0-9]{0,8}(?:-L?[1-9][0-9]{0,8})?")?lineRef:null;
                boolean redacted=!path.equals(safePath)||!branch.equals(safeBranch)||!(owner+"/"+repo).equals(safeRepo);
                String link=redacted?null:"https://github.com/"+encode(owner)+"/"+encode(repo)+"/blob/"+encode(branch)+"/"+String.join("/",Arrays.stream(path.split("/")).map(SecretSourceDetails::encode).toList())+(lines==null?"":"#"+lines.replaceAll("-(?!L)","-L"));
                return facts("status","AVAILABLE","kind","GITHUB_FILE","label",safeRepo+"/"+safePath,"repository",safeRepo,"branch",safeBranch,"path",safePath,"line",lines,"sourceUrl",link);
            }
            if("AWS".equals(provider)&&"aws".equals(uri.getScheme())&&uri.getHost()!=null&&uri.getHost().matches("[0-9]{12}")) {
                String[] parts=uri.getRawPath().split("/",-1);
                if(parts.length<3||!parts[1].matches("[a-z]{2}(?:-gov)?-[a-z0-9-]+-[0-9]+"))return unavailable;
                String resource=safe(String.join("/",Arrays.stream(parts).skip(2).map(SecretSourceDetails::decode).toList()));
                if(resource==null)return unavailable;
                return facts("status","AVAILABLE","kind","AWS_RESOURCE","label",parts[1]+" · "+resource,"region",parts[1],"resource",resource,"line",lineRef!=null&&lineRef.matches("L[1-9][0-9]{0,8}(?:-L?[1-9][0-9]{0,8})?")?lineRef:null,"sourceUrl",null);
            }
        } catch(RuntimeException ignored) { /* Invalid or obsolete coordinates are never echoed. */ }
        return unavailable;
    }
}
