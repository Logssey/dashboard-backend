package jakarta.servlet.annotation;

import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/** Fixture stub with the Servlet 6.1 name. */
@Retention(RetentionPolicy.RUNTIME)
public @interface HttpConstraint {
    String[] rolesAllowed() default {};
}
