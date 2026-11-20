package com.example.generic;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Through an interface: D = ScheduleRequest (javax.xml.datatype.Duration field, CVE-2026-68497). */
@RestController
@RequestMapping("/schedules")
public class ScheduleController implements ImportApi<ScheduleRequest> {}
