package org.springframework.context.annotation;

import java.lang.annotation.*;

import org.springframework.stereotype.Component;
@Component
@Target({ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Configuration {
}
