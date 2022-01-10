package no.nav.token.support.spring.reactive.api;

import no.nav.token.support.spring.reactive.EnableReactiveJwtTokenValidationConfiguration;
import org.springframework.context.annotation.Import;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Documented
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Import({
    EnableReactiveJwtTokenValidationConfiguration.class
})
public @interface EnableReactiveJwtTokenValidation {
    String[] ignore() default {"org.springframework"};
}
