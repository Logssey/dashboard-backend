package com.example.generic;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Direct subclass: T = ItemRequest (BigDecimal field, CVE-2026-89407). */
@RestController
@RequestMapping("/items")
public class ItemController extends CrudController<ItemRequest> {}
