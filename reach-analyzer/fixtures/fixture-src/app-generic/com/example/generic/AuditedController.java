package com.example.generic;

/** An intermediate generic layer: U is passed on to CrudController's T. */
public abstract class AuditedController<U> extends CrudController<U> {}
