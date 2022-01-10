package spring.integrationtest;

import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.RequiredIssuers;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.token.support.spring.reactive.ProtectedRestController;
import org.springframework.web.bind.annotation.GetMapping;
import reactor.core.publisher.Mono;

@ProtectedRestController(issuer = AProtectedRestController.ISSUER_SHORTNAME)
public class AProtectedRestController {
    static final String ISSUER_SHORTNAME = "knownissuer";
    private static final String ISSUER_SHORTNAME2 = "knownissuer2";
    private static final String ISSUER_SHORTNAME3 = "knownissuer3";
    static final String UNPROTECTED = "/unprotected";
    static final String PROTECTED = "/protected";
    static final String PROTECTED_WITH_CLAIMS = "/protected/withclaims";
    static final String PROTECTED_WITH_CLAIMS2 = "/protected/withclaims2";
    static final String PROTECTED_WITH_CLAIMS3 = "/protected/withclaims3";
    static final String PROTECTED_WITH_MULTIPLE = "/protected/withmultipleissuers";

    static final String PROTECTED_WITH_CLAIMS_ANY_CLAIMS = "/protected/anyclaims";

    @GetMapping(PROTECTED)
    public Mono<String> protectedMethod() {
        return Mono.just("protected");
    }

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME, claimMap = {"importantclaim=vip", "acr=Level4"})
    @GetMapping(PROTECTED_WITH_CLAIMS)
    public String protectedWithClaimsMethod() {
        return "protected with some required claims";
    }

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME2)
    @GetMapping(PROTECTED_WITH_CLAIMS2)
    public String protectedWithClaimsMethod2() {
        return "protected with some required claims";
    }

    @RequiredIssuers({
        @ProtectedWithClaims(issuer = ISSUER_SHORTNAME2, claimMap = {"claim1=1", "claim2=2"}),
        @ProtectedWithClaims(issuer = ISSUER_SHORTNAME, claimMap = {"claim1=3", "claim2=4"})})

    @GetMapping(PROTECTED_WITH_MULTIPLE)
    public String protectedWith2IssuersMethod() {
        return "protected with some required claims";
    }

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME3)
    @GetMapping(PROTECTED_WITH_CLAIMS3)
    public String protectedWithClaimsMethod3() {
        return "protected with some required claims and configurable JWKSet";
    }

    @ProtectedWithClaims(issuer = ISSUER_SHORTNAME, claimMap = {"claim1=1", "claim2=2"}, combineWithOr = true)
    @GetMapping(PROTECTED_WITH_CLAIMS_ANY_CLAIMS)
    public String protectedWithClaimsAnyClaimMethod() {
        return "protected with any of the registered claims";
    }

    @Unprotected
    @GetMapping(UNPROTECTED)
    public Mono<String> unprotectedMethod() {
        return Mono.just("unprotected");
    }
}
