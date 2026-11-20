package com.example.generic;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Control: a raw supertype gives no type argument, so nothing is added for it. */
@RestController
@RequestMapping("/raw")
@SuppressWarnings("rawtypes")
public class RawController extends CrudController {}
