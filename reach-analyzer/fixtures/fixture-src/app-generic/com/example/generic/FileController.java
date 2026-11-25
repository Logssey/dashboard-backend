package com.example.generic;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Two levels up: T = U = FileRequest (java.nio.file.Path field, CVE-2026-19032). */
@RestController
@RequestMapping("/files")
public class FileController extends AuditedController<FileRequest> {}
