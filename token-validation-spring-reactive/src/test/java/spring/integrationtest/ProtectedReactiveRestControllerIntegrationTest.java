package spring.integrationtest;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenRequest;
import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.token.OAuth2TokenCallback;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static no.nav.security.token.support.test.JwtTokenGenerator.ACR;
import static no.nav.security.token.support.test.JwtTokenGenerator.AUD;
import static spring.integrationtest.AProtectedRestController.PROTECTED;
import static spring.integrationtest.AProtectedRestController.UNPROTECTED;


@WebFluxTest(controllers = {AProtectedRestController.class})
@ContextConfiguration(classes = {ProtectedApplication.class, ProtectedApplicationConfig.class})
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class ProtectedReactiveRestControllerIntegrationTest {

    @Autowired
    private MockOAuth2Server mockOAuth2Server;

    private WebTestClient webTestClient;

    @BeforeEach
    void initialiseRestAssuredMockMvcWebApplicationContext() {
        webTestClient = WebTestClient.bindToController(AProtectedRestController.class).build();
        //Collection<Filter> filterCollection = webApplicationContext.getBeansOfType(Filter.class).values();
        //Filter[] filters = filterCollection.toArray(new Filter[0]);
        // WebTestClientConfigurer mockMvcConfigurer = (builder, httpHandlerBuilder, connector) -> builder.build();
        // webTestClient.mutateWith(mockMvcConfigurer);
    }


    @Test
    void unprotectedMethod() {
        webTestClient.get()
            .uri(UNPROTECTED)
            .exchange()
            .expectStatus().isOk()
            .expectBody(String.class)
            .isEqualTo("unprotected");
    }

    @Test
    void noTokenInRequest() {
        webTestClient
            .get()
            .uri(PROTECTED)
            .exchange()
            .expectStatus().isUnauthorized();
    }

    //  @Test
    //  void unparseableTokenInRequest() {
    //      expectStatusCode(PROTECTED, "unparseable", HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void unsignedTokenInRequest() {
    //      JWT jwt = new PlainJWT(jwtClaimsSetKnownIssuer());
    //      expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void signedTokenInRequestUnknownIssuer() {
    //      JWT jwt = issueToken("unknown", jwtClaimsSet(AUD));
    //      expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void signedTokenInRequestUnknownAudience() {
    //      JWT jwt = issueToken("knownissuer", jwtClaimsSet("unknown"));
    //      expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void signedTokenInRequestProtectedWithClaimsMethodMissingRequiredClaims() {
    //      JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
    //              .claim("importantclaim", "vip")
    //              .build();
    //      expectStatusCode(PROTECTED_WITH_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void signedTokenInRequestKeyFromUnknownSource() {
    //      JWTClaimsSet jwtClaimsSet = jwtClaimsSetKnownIssuer();
    //      JWT jwt = createSignedJWT(JwkGenerator.createJWK(JwkGenerator.DEFAULT_KEYID, JwkGenerator.generateKeyPair()), jwtClaimsSet);
    //      expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void signedTokenInRequestProtectedMethodShouldBeOk() {
    //      JWT jwt = issueToken("knownissuer", jwtClaimsSetKnownIssuer());
    //      expectStatusCode(PROTECTED, jwt.serialize(), HttpStatus.OK);
    //  }

    //  @Test
    //  @DisplayName("Token matches one of the configured issuers, including claims")
    //  void multipleIssuersOneOKIncludingClaims() {
    //      JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
    //              .claim("claim1", "3")
    //              .claim("claim2", "4")
    //              .claim("acr", "Level4")
    //              .build();
    //      JWT jwt = issueToken("knownissuer", jwtClaimsSet);
    //      expectStatusCode(PROTECTED_WITH_MULTIPLE, jwt.serialize(), HttpStatus.OK);
    //  }

    //  @Test
    //  @DisplayName("Token matches one of the configured issuers, but not all claims match")
    //  void multipleIssuersOneIssuerMatchesButClaimsDont() {
    //      JWT jwt = issueToken("knownissuer", jwtClaimsSetKnownIssuer());
    //      expectStatusCode(PROTECTED_WITH_MULTIPLE, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  @DisplayName("Token matches none of the configured issuers")
    //  void multipleIssuersNoIssuerMatches() {
    //      JWT jwt = issueToken("knownissuer3", jwtClaimsSetKnownIssuer());
    //      expectStatusCode(PROTECTED_WITH_MULTIPLE, jwt.serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  @Test
    //  void signedTokenInRequestProtectedWithClaimsMethodShouldBeOk() {
    //      JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
    //              .claim("importantclaim", "vip")
    //              .claim("acr", "Level4")
    //              .build();

    //      expectStatusCode(PROTECTED_WITH_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.OK);

    //      JWTClaimsSet jwtClaimsSet2 = defaultJwtClaimsSetBuilder()
    //              .claim("claim1", "1")
    //              .build();

    //      expectStatusCode(PROTECTED_WITH_CLAIMS_ANY_CLAIMS, issueToken("knownissuer", jwtClaimsSet2).serialize(), HttpStatus.OK);
    //  }

    //  @Test
    //  void signedTokenInRequestProtectedWithArrayClaimsMethodShouldBeOk() {
    //      JWTClaimsSet jwtClaimsSet = defaultJwtClaimsSetBuilder()
    //          .claim("claim1", List.of("1"))
    //          .build();

    //      expectStatusCode(PROTECTED_WITH_CLAIMS_ANY_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.OK);
    //  }

    //  @Test
    //  void signedTokenInRequestWithoutSubAndAudClaimsShouldBeOk() {
    //      Date now = new Date();
    //      JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
    //              .jwtID(UUID.randomUUID().toString())
    //              .claim("auth_time", now)
    //              .notBeforeTime(now)
    //              .issueTime(now)
    //              .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)))
    //              .build();

    //      expectStatusCode(PROTECTED_WITH_CLAIMS2, issueToken("knownissuer2", jwtClaimsSet).serialize(), HttpStatus.OK);
    //  }

    //  @Test
    //  void signedTokenInRequestWithoutSubAndAudClaimsShouldBeNotBeOk() {
    //      Date now = new Date();
    //      JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
    //              .jwtID(UUID.randomUUID().toString())
    //              .claim("auth_time", now)
    //              .notBeforeTime(now)
    //              .issueTime(now)
    //              .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)))
    //              .build();

    //      expectStatusCode(PROTECTED_WITH_CLAIMS, issueToken("knownissuer", jwtClaimsSet).serialize(), HttpStatus.UNAUTHORIZED);
    //  }

    //  private static void expectStatusCode(String uri, String token, HttpStatus httpStatus) {
    //      given()
    //              .header("Authorization", "Bearer " + token)
    //              .when()
    //              .get(uri)
    //              .then()
    //              .log().ifValidationFails()
    //              .statusCode(httpStatus.value());
    //  }

    private static JWTClaimsSet.Builder defaultJwtClaimsSetBuilder() {
        Date now = new Date();
        return new JWTClaimsSet.Builder()
            .subject("testsub")
            .audience(AUD)
            .jwtID(UUID.randomUUID().toString())
            .claim("auth_time", now)
            .notBeforeTime(now)
            .issueTime(now)
            .expirationTime(new Date(now.getTime() + TimeUnit.MINUTES.toMillis(1)));
    }

    private static JWTClaimsSet jwtClaimsSetKnownIssuer() {
        return jwtClaimsSet(AUD);
    }

    private static JWTClaimsSet jwtClaimsSet(String audience) {
        return buildClaimSet("testsub", audience, ACR, TimeUnit.MINUTES.toMillis(1));
    }

    public static JWTClaimsSet buildClaimSet(String subject, String audience, String authLevel,
                                             long expiry) {
        Date now = new Date();
        return new JWTClaimsSet.Builder()
            .subject(subject)
            .audience(audience)
            .jwtID(UUID.randomUUID().toString())
            .claim("acr", authLevel)
            .claim("ver", "1.0")
            .claim("nonce", "myNonce")
            .claim("auth_time", now)
            .notBeforeTime(now)
            .issueTime(now)
            .expirationTime(new Date(now.getTime() + expiry)).build();
    }

    private SignedJWT issueToken(String issuerId, JWTClaimsSet jwtClaimsSet) {
        OAuth2TokenCallback callback = new OAuth2TokenCallback() {
            @Override
            public long tokenExpiry() {
                return 30;
            }

            @Override
            public String subject(@NotNull TokenRequest tokenRequest) {
                return jwtClaimsSet.getSubject();
            }

            @NotNull
            @Override
            public String issuerId() {
                return issuerId;
            }

            @Override
            public List<String> audience(@NotNull TokenRequest tokenRequest) {
                return jwtClaimsSet.getAudience();
            }

            @NotNull
            @Override
            public Map<String, Object> addClaims(@NotNull TokenRequest tokenRequest) {
                return jwtClaimsSet.getClaims();
            }
        };
        return mockOAuth2Server.issueToken(issuerId, "client_id", callback);
    }
}
