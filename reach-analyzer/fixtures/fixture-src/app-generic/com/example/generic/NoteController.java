package com.example.generic;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Control: a bound type with nothing a rule looks for. */
@RestController
@RequestMapping("/notes")
public class NoteController extends CrudController<NoteRequest> {}
