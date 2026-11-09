package com.example.risky;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import java.nio.file.Path;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** CVE-2026-19032 (Path field) and CVE-2026-83557 (@JsonTypeInfo on a Comparable field) positive controls. */
@RestController
public class ExtraController {
    public record ExportRequest(String name, Path target) {
    }

    public record SortRequest(@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS) Comparable<?> key) {
    }

    @PostMapping("/export")
    public String export(@RequestBody ExportRequest request) {
        return String.valueOf(request.target());
    }

    @PostMapping("/sort")
    public String sort(@RequestBody SortRequest request) {
        return String.valueOf(request.key());
    }
}
