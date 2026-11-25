package com.logssey.secret.query;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

/** Authorized source coordinates only. Never returns file contents, auth refs or key identities. */
public final class SecretSourceDetails {
    private SecretSourceDetails() { }
    private static final Pattern CREDENTIAL = Pattern.compile("AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]+|(?:secret_|ntn_)[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9_-]{20,}");
    private static String safe(String value) {
        if(value==null || value.length()>700 || value.chars().anyMatch(c->c<32||c==127)||value.contains("\\")) return null;
        return CREDENTIAL.matcher(value).replaceAll("[마스킹]");
    }
    private static String decode(String value) { return URLDecoder.decode(value.replace("+","%2B"),StandardCharsets.UTF_8); }
    private static String encode(String value) { return URLEncoder.encode(value,StandardCharsets.UTF_8).replace("+","%20"); }

    public record GitHubTarget(String repository,String branch,String path) { }

    /** Returns display coordinates from the supplied approval snapshot without echoing its URI. */
    public static GitHubTarget githubTarget(String provider,String contentType,String approvedRef) {
        if(!"GITHUB".equals(provider)||!"GITHUB_REPOSITORY_FILES".equals(contentType)
                ||approvedRef==null||approvedRef.length()>500)return null;
        try {
            var uri=URI.create(approvedRef);
            if(!"github".equals(uri.getScheme())||uri.getRawUserInfo()!=null||uri.getPort()!=-1
                    ||uri.getRawQuery()!=null||uri.getRawFragment()!=null||uri.getHost()==null)return null;
            String[] parts=uri.getRawPath().split("/",-1);
            if(parts.length<4||!parts[parts.length-1].isEmpty())return null;
            String owner=uri.getHost(),repo=decode(parts[1]),branch=decode(parts[2]);
            if(!owner.matches("[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
                    ||!repo.matches("[A-Za-z0-9_.-]{1,100}")||Set.of(".","..").contains(repo)
                    ||branch.isBlank()||branch.length()>200||branch.startsWith("/")||branch.endsWith("/")
                    ||branch.contains("..")||branch.contains("//")||branch.contains("@{")
                    ||branch.chars().anyMatch(c->c<=32||c==127||"\\?#*[]~^:".indexOf(c)>=0))return null;
            var pathParts=Arrays.stream(parts).skip(3).limit(parts.length-4L)
                    .map(SecretSourceDetails::decode).toList();
            if(pathParts.stream().anyMatch(part->part.isBlank()||part.equals(".")||part.equals("..")))return null;
            String path=pathParts.isEmpty()?"":String.join("/",pathParts)+"/";
            if(path.length()>250||path.contains("%")
                    ||path.chars().anyMatch(c->c<32||c==127||"\\?#*:".indexOf(c)>=0))return null;
            if(!path.isEmpty()&&Arrays.stream(path.substring(0,path.length()-1).split("/",-1))
                    .anyMatch(part->part.isBlank()||part.equals(".")||part.equals("..")))return null;
            String repository=owner+"/"+repo;
            if(!repository.equals(safe(repository))||!branch.equals(safe(branch))||!path.equals(safe(path)))return null;
            return new GitHubTarget(repository,branch,path);
        }catch(RuntimeException ignored) {
            return null;
        }
    }

    public static String scopeLabel(String provider,String approvedRef,long scopeId) {
        try {
            var uri=URI.create(approvedRef);
            if(uri.getRawUserInfo()!=null||uri.getPort()!=-1||uri.getRawQuery()!=null||uri.getRawFragment()!=null)return "검사 대상 #"+scopeId;
            var p=uri.getRawPath().split("/",-1);
            if("NOTION".equals(provider)&&approvedRef.matches(com.logssey.secret.notion.NotionScopeSql.REFERENCE_PATTERN)) {
                return "Notion 페이지 "+com.logssey.secret.notion.NotionScopeSql.pageId(approvedRef).substring(0,8);
            }
            if("GITHUB".equals(provider)&&"github".equals(uri.getScheme())&&uri.getHost()!=null&&p.length>=4) {
                if(p.length==4)return safe(uri.getHost()+"/"+decode(p[1])+" · "+decode(p[2])+" · 전체 저장소");
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
    public static Map<String,Object> describeObserved(String provider,String approvedRef,String contextRef,
                                                     String contextStatus,String sourceRef,String lineRef) {
        var details=new java.util.LinkedHashMap<>(describe(provider,
                "GITHUB".equals(provider)?contextRef:approvedRef,sourceRef,lineRef));
        if("GITHUB".equals(provider)) {
            var current=describe(provider,approvedRef,sourceRef,lineRef);
            if("AVAILABLE".equals(details.get("status"))
                    && (!"AVAILABLE".equals(current.get("status"))
                      || !java.util.Objects.equals(current.get("branch"),details.get("branch")))) {
                details=new java.util.LinkedHashMap<>(facts("status","UNAVAILABLE","label","발견 위치 확인 필요",
                        "reasonCode","SOURCE_APPROVAL_CHANGED"));
            }
            details.put("contextStatus",Set.of("OBSERVED","RECONSTRUCTED").contains(contextStatus==null?"":contextStatus)
                    ?contextStatus:"UNKNOWN");
        }
        return details;
    }

    public static Map<String,Object> describe(String provider,String approvedRef,String sourceRef,String lineRef) {
        var unavailable=facts("status","UNAVAILABLE","label","발견 위치 확인 필요","reasonCode","SOURCE_COORDINATES_UNAVAILABLE");
        try {
            var uri=URI.create(approvedRef);
            if(uri.getUserInfo()!=null||uri.getPort()!=-1||uri.getQuery()!=null||uri.getFragment()!=null) return unavailable;
            if("NOTION".equals(provider)&&approvedRef.matches(com.logssey.secret.notion.NotionScopeSql.REFERENCE_PATTERN)) {
                String page=com.logssey.secret.notion.NotionScopeSql.pageId(approvedRef);
                String prefix="notion/pages/"+page+"/";
                if(sourceRef==null||!sourceRef.startsWith(prefix))return unavailable;
                String location=sourceRef.substring(prefix.length());
                String block=null;
                if(location.startsWith("blocks/")) {
                    block=location.substring("blocks/".length());
                    if(!block.matches("[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"))return unavailable;
                } else if(!"title".equals(location))return unavailable;
                String link="https://www.notion.so/"+page.replace("-","")
                        +(block==null?"":"#"+block.replace("-",""));
                String line=lineRef!=null&&lineRef.matches("L[1-9][0-9]{0,8}(?:-L?[1-9][0-9]{0,8})?")?lineRef:null;
                return facts("status","AVAILABLE","kind","NOTION_PAGE","label","Notion 페이지 "+page.substring(0,8)
                        +(block==null?" · 제목":" · 블록"),"pageId",page,"blockId",block,"line",line,"sourceUrl",link);
            }
            if("GITHUB".equals(provider)&&"github".equals(uri.getScheme())) {
                String[] parts=uri.getRawPath().split("/",-1);
                if(parts.length<4 || !parts[parts.length-1].isEmpty() || uri.getHost()==null) return unavailable;
                String owner=uri.getHost(),repo=decode(parts[1]),branch=decode(parts[2]);
                if(!owner.matches("[A-Za-z0-9-]{1,39}")||!repo.matches("[A-Za-z0-9_.-]{1,100}")||branch.isBlank())return unavailable;
                String prefix=parts.length==4?"":String.join("/",Arrays.stream(parts).skip(3).limit(parts.length-4L).map(SecretSourceDetails::decode).toList())+"/";
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
