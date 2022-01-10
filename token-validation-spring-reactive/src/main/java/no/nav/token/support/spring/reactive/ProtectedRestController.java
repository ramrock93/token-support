package no.nav.token.support.spring.reactive;

import no.nav.security.token.support.core.api.ProtectedWithClaims;
import org.springframework.core.annotation.AliasFor;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@Documented
@ProtectedWithClaims(issuer = "must-be-set-to-issuer")
@Target(TYPE)
@Retention(RUNTIME)
@RequestMapping
public @interface ProtectedRestController {
    @AliasFor(annotation = RequestMapping.class, attribute = "value")
    String[] value() default "/";

    @AliasFor(annotation = ProtectedWithClaims.class, attribute = "claimMap")
    String[] claimMap() default "acr=Level4";

    @AliasFor(annotation = ProtectedWithClaims.class, attribute = "issuer")
    String issuer();

    @AliasFor(annotation = RequestMapping.class, attribute = "produces")
    String[] produces() default APPLICATION_JSON_VALUE;

}
