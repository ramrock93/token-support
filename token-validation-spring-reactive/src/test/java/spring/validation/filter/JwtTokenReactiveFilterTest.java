package spring.validation.filter;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import net.minidev.json.JSONArray;
import no.nav.security.token.support.core.api.Protected;
import no.nav.security.token.support.core.api.ProtectedWithClaims;
import no.nav.security.token.support.core.api.Unprotected;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.security.token.support.core.jwt.JwtToken;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;
import no.nav.token.support.spring.reactive.validation.filter.JwtTokenReactiveFilter;
import no.nav.token.support.spring.reactive.validation.filter.SpringJwtTokenAnnotationHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.HandlerAdapter;
import org.springframework.web.reactive.result.method.RequestMappingInfo;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class JwtTokenReactiveFilterTest {

    private AnnotationAttributes annotationAttrs;
    private JwtTokenAnnotationHandler jwtTokenAnnotationHandler;
    private JwtTokenReactiveFilter jwtTokenReactiveFilter;
    private MockServerWebExchange exchange;
    private RequestMappingHandlerMapping requestMappingHandlerMapping;
    private TokenValidationContextHolder contextHolder;
    private WebFilterChain filterChain;
    private RequestMappingHandlerAdapter requestMappingHandlerAdapter;
    private HandlerAdapter handlerAdapter;

    @BeforeEach
    void setup() throws Exception {
        contextHolder = createContextHolder();
        contextHolder.setTokenValidationContext(new TokenValidationContext(Collections.emptyMap()));
        jwtTokenAnnotationHandler = new SpringJwtTokenAnnotationHandler(contextHolder);
        Map<String, Object> annotationAttributesMap = new HashMap<>();
        annotationAttributesMap.put("ignore", new String[]{"org.springframework", IgnoreClass.class.getName()});
        annotationAttrs = AnnotationAttributes.fromMap(annotationAttributesMap);
        requestMappingHandlerMapping = new RequestMappingHandlerMapping();
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/test"));
        requestMappingHandlerAdapter = new RequestMappingHandlerAdapter();
        jwtTokenReactiveFilter = new JwtTokenReactiveFilter(annotationAttrs, jwtTokenAnnotationHandler);
        filterChain = createWebFilterChain();
        handlerAdapter = jwtTokenReactiveFilter.handlerAdapter(requestMappingHandlerAdapter);
    }

    @Test
    void classIsMarkedAsIgnore() throws Exception {
        String methodName = "test";
        HandlerMethod handlerMethod = handlerMethod(new IgnoreClass(), methodName);
        assertNotNull(handlerAdapter.handle(exchange, handlerMethod));
    }

    //  @Test
    //  void notAnnotatedShouldThrowException() {
    //      String methodName = "test";
    //      createJwtTokenReactiveFilter(handlerMethod(new NotAnnotatedClass(), methodName), methodName);
    //      assertThatExceptionOfType(ResponseStatusException.class).isThrownBy(
    //              () -> jwtTokenReactiveFilter.filter(exchange, filterChain))
    //          .withMessageContaining(HttpStatus.NOT_IMPLEMENTED.toString());
    //  }
//
    //  @Test
    //  void methodIsUnprotectedAccessShouldBeAllowed() {
    //      String methodName = "test";
    //      createJwtTokenReactiveFilter(handlerMethod(new UnprotectedClass(), methodName), methodName);
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtected() {
    //      String methodName = "test";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedClass(), methodName), methodName);
//
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtectedOnUnprotectedClass() {
    //      String methodName = "protectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new UnprotectedClassProtectedMethod(), methodName), methodName);
//
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeUnprotectedOnProtectedClass() {
    //      String methodName = "unprotectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedClassUnprotectedMethod(), methodName), methodName);
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtectedWithClaims() {
    //      String methodName = "protectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedClassProtectedWithClaimsMethod(), methodName), methodName);
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtectedOnClassProtectedWithClaims() {
    //      String methodName = "protectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedClassProtectedWithClaimsMethod(), methodName), methodName);
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodIsUnprotectedAccessShouldBeAllowedMeta() {
    //      String methodName = "test";
    //      createJwtTokenReactiveFilter(handlerMethod(new UnprotectedClassMeta(), methodName), methodName);
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtectedOnUnprotectedClassMeta() {
    //      String methodName = "protectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new UnprotectedClassProtectedMethodMeta(), methodName), methodName);
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeUnprotectedOnProtectedClassMeta() {
    //      String methodName = "unprotectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedClassUnprotectedMethodMeta(), methodName), methodName);
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtectedOnProtectedSuperClassMeta() {
    //      String methodName = "test";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedSubClassMeta(), methodName), methodName);
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void unprotectedMetaClassProtectedMethodMeta() {
    //      String methodName = "protectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new UnprotectedClassProtectedMethodMeta(), methodName), methodName);
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }
//
    //  @Test
    //  void methodShouldBeProtectedOnClassProtectedWithClaimsMeta() {
    //      String methodName = "protectedMethod";
    //      createJwtTokenReactiveFilter(handlerMethod(new ProtectedWithClaimsClassProtectedMethodMeta(), methodName), methodName);
    //      assertThrows(JwtTokenUnauthorizedException.class,
    //          () -> jwtTokenReactiveFilter.filter(exchange, filterChain));
    //      setupValidOidcContext();
    //      assertNotNull(jwtTokenReactiveFilter.filter(exchange, filterChain));
    //  }

    //private void createJwtTokenReactiveFilter(HandlerMethod handlerMethod, String methodName) {
    //    RequestMappingInfo mappingInfo = createRequestMappingInfo();
    //    assertDoesNotThrow(
    //        () -> requestMappingHandlerMapping.registerMapping(mappingInfo, handlerMethod, handlerMethod.getBean().getClass().getMethod(methodName)));
    //    jwtTokenReactiveFilter = new JwtTokenReactiveFilter(annotationAttrs, jwtTokenAnnotationHandler);
    //}

    private RequestMappingInfo createRequestMappingInfo() {
        return RequestMappingInfo
            .paths("/test")
            .methods(RequestMethod.GET)
            .build();
    }

    private WebFilterChain createWebFilterChain() {
        return filterExchange -> Mono.empty();
    }

    private static TokenValidationContextHolder createContextHolder() {
        return new TokenValidationContextHolder() {
            TokenValidationContext validationContext;

            @Override
            public TokenValidationContext getTokenValidationContext() {
                return validationContext;
            }

            @Override
            public void setTokenValidationContext(TokenValidationContext tokenValidationContext) {
                this.validationContext = tokenValidationContext;
            }
        };
    }

    private static HandlerMethod handlerMethod(Object object, String method) {
        try {
            return new HandlerMethod(object, method);
        } catch (NoSuchMethodException e) {
            throw new RuntimeException(e);
        }
    }

    private void setupValidOidcContext() {
        JwtToken claims = createJwtToken("aclaim", "value");
        TokenValidationContext context = createOidcValidationContext("issuer1", claims);
        contextHolder.setTokenValidationContext(context);
    }

    private static JwtToken createJwtToken(String claimName, String claimValue) {
        final JSONArray groupsValues = new JSONArray();
        groupsValues.add("123");
        groupsValues.add("456");

        JWT jwt = new PlainJWT(new JWTClaimsSet.Builder()
            .subject("subject")
            .issuer("http//issuer1")
            .claim("acr", "Level4")
            .claim("groups", groupsValues)
            .claim(claimName, claimValue).build());
        return new JwtToken(jwt.serialize());
    }

    private static TokenValidationContext createOidcValidationContext(String issuerShortName, JwtToken jwtToken) {
        Map<String, JwtToken> map = new ConcurrentHashMap<>();
        map.put(issuerShortName, jwtToken);
        return new TokenValidationContext(map);
    }

    private static class IgnoreClass {
        public void test() {
        }
    }

    private static class NotAnnotatedClass {
        public void test() {
        }
    }

    @Protected
    private static class ProtectedClass {
        public void test() {
        }
    }

    @Unprotected
    private class UnprotectedClass {
        public void test() {
        }
    }

    @Unprotected
    private class UnprotectedClassProtectedMethod {
        @Protected
        public void protectedMethod() {
        }

        public void unprotectedMethod() {
        }
    }

    @Protected
    private class ProtectedClassUnprotectedMethod {
        public void protectedMethod() {
        }

        @Unprotected
        public void unprotectedMethod() {
        }
    }

    @Protected
    private class ProtectedClassProtectedWithClaimsMethod {
        @ProtectedWithClaims(issuer = "issuer1")
        public void protectedMethod() {
        }

        @Unprotected
        public void unprotectedMethod() {
        }

        public void unprotected() {
        }
    }

    @UnprotectedMeta
    private class UnprotectedClassMeta {
        public void test() {
        }
    }

    @UnprotectedMeta
    private class UnprotectedClassProtectedMethodMeta {
        @ProtectedMeta
        public void protectedMethod() {
        }
    }

    @ProtectedMeta
    private class ProtectedClassUnprotectedMethodMeta {
        public void protectedMethod() {
        }

        @UnprotectedMeta
        public void unprotectedMethod() {
        }
    }

    @ProtectedWithClaimsMeta
    private class ProtectedWithClaimsClassProtectedMethodMeta {
        @ProtectedMeta
        public void protectedMethod() {
        }

        @UnprotectedMeta
        public void unprotectedMethod() {
        }

        public void protectedWithClaimsMethod() {
        }
    }

    @ProtectedMeta
    private class ProtectedSuperClassMeta {

    }

    private class ProtectedSubClassMeta extends ProtectedSuperClassMeta {
        public void test() {
        }
    }
}
