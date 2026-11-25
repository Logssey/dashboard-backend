package com.logssey.compliance;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/** Worker에 전달할 수 있는 Prowler 5.46.0 AWS Service와 Check 허용 목록. */
@Component
public class ProwlerScopeCatalog {

    private final ScopeCatalog file;
    private final Set<String> services;
    private final Set<String> checks;
    private final Map<String, String> checkServices;

    public ProwlerScopeCatalog() {
        try (var input = new ClassPathResource("compliance/prowler-aws-scope-catalog.json").getInputStream()) {
            this.file = JsonMapper.builder().build().readValue(input, ScopeCatalog.class);
        } catch (IOException e) {
            throw new IllegalStateException("Prowler 점검 범위 카탈로그를 읽을 수 없습니다.", e);
        }
        if (file.schemaVersion() != 1 || !"aws".equals(file.provider())
                || file.services() == null || file.checks() == null
                || file.services().size() != file.serviceCount() || file.checks().size() != file.checkCount()) {
            throw new IllegalStateException("지원하지 않는 Prowler 점검 범위 카탈로그입니다.");
        }
        this.services = Set.copyOf(file.services());
        var indexed = new LinkedHashMap<String, String>();
        for (var check : file.checks()) {
            if (!services.contains(check.service()) || indexed.put(check.id(), check.service()) != null) {
                throw new IllegalStateException("잘못된 Prowler Check 카탈로그: " + check.id());
            }
        }
        this.checkServices = Map.copyOf(indexed);
        this.checks = checkServices.keySet();
    }

    public String version() { return file.version(); }
    public String commit() { return file.commit(); }
    public List<String> services() { return file.services(); }
    public List<Check> checkItems() { return file.checks(); }
    public boolean supportsService(String service) { return services.contains(service); }
    public boolean supportsCheck(String check) { return checks.contains(check); }
    public String serviceForCheck(String check) { return checkServices.get(check); }

    public record ScopeCatalog(int schemaVersion, String provider, String version, String commit,
                               int checkCount, int serviceCount, List<String> services, List<Check> checks) {}
    public record Check(String id, String service) {}
}
