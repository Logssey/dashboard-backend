package org.jspecify.annotations;

import java.lang.annotation.*;

@Target({ElementType.TYPE_USE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface Nullable {
}
