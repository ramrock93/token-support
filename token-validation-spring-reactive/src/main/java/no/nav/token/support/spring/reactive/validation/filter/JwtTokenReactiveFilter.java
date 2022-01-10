package no.nav.token.support.spring.reactive.validation.filter;

import no.nav.security.token.support.core.exceptions.AnnotationRequiredException;
import no.nav.security.token.support.core.validation.JwtTokenAnnotationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.reactive.HandlerAdapter;
import org.springframework.web.reactive.HandlerResult;
import org.springframework.web.reactive.result.method.annotation.RequestMappingHandlerAdapter;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.util.annotation.NonNull;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class JwtTokenReactiveFilter extends RequestMappingHandlerAdapter implements ApplicationContextAware {

    private final Logger logger = LoggerFactory.getLogger(JwtTokenReactiveFilter.class);
    private final JwtTokenAnnotationHandler jwtTokenAnnotationHandler;
    private final String[] ignoreConfig;
    private final Map<Object, Boolean> handlerFlags = new ConcurrentHashMap<>();
    // private final RequestMappingHandlerMapping requestMappingHandlerMapping;

    public JwtTokenReactiveFilter(
        AnnotationAttributes enableJwtTokenValidation,
        JwtTokenAnnotationHandler jwtTokenAnnotationHandler
        // RequestMappingHandlerMapping requestMappingHandlerMapping
    ) {
        this.jwtTokenAnnotationHandler = jwtTokenAnnotationHandler;
        //this.requestMappingHandlerMapping = requestMappingHandlerMapping;

        if (enableJwtTokenValidation != null) {
            ignoreConfig = enableJwtTokenValidation.getStringArray("ignore");
        } else {
            // nothing explicitly configured to be ignored, intercept everything
            ignoreConfig = new String[0];
        }
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public HandlerAdapter handlerAdapter(RequestMappingHandlerAdapter requestMappingHandlerAdapter) {
        return new HandlerAdapter() {

            @Override
            public boolean supports(@NonNull Object handler) {
                return handler instanceof HandlerMethod;
            }

            @Override
            @NonNull
            public Mono<HandlerResult> handle(@NonNull ServerWebExchange exchange, @NonNull Object handler) {
                HandlerMethod h = (HandlerMethod) handler;
                System.out.println("YOLO");
                System.out.println(h.getBean());
                if (shouldIgnore(h.getBean())) {
                    return requestMappingHandlerAdapter.handle(exchange, handler);
                }
                try {
                    if (jwtTokenAnnotationHandler.assertValidAnnotation(h.getMethod())) {
                        return requestMappingHandlerAdapter.handle(exchange, handler);
                    }
                } catch (AnnotationRequiredException e) {
                    logger.error("received AnnotationRequiredException from JwtTokenAnnotationHandler. return " +
                        "status={}", HttpStatus.NOT_IMPLEMENTED, e);
                    throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED, "endpoint not accessible");
                } catch (Exception e) {
                    throw new JwtTokenUnauthorizedException(e);
                }
                return requestMappingHandlerAdapter.handle(exchange, handler);

            }
        };
    }

    //  @Override
    //  @NonNull
    //  public Mono<Void> filter(@NonNull ServerWebExchange exchange, @NonNull WebFilterChain chain) {
    //      HandlerMethod handler = (HandlerMethod) requestMappingHandlerMapping.getHandler(exchange).toProcessor().peek();
    //      System.out.println("YOLO");
    //      System.out.println(handler.getBean());
    //      if (handler != null && shouldIgnore(handler.getBean())) {
    //          return chain.filter(exchange);
    //      }
    //      try {
    //          if (handler != null && jwtTokenAnnotationHandler.assertValidAnnotation(handler.getMethod())) {
    //              return chain.filter(exchange);
    //          }
    //      } catch (AnnotationRequiredException e) {
    //          logger.error("received AnnotationRequiredException from JwtTokenAnnotationHandler. return " +
    //              "status={}", HttpStatus.NOT_IMPLEMENTED, e);
    //          throw new ResponseStatusException(HttpStatus.NOT_IMPLEMENTED, "endpoint not accessible");
    //      } catch (Exception e) {
    //          throw new JwtTokenUnauthorizedException(e);
    //      }
    //      return Mono.empty();
    //  }

    private boolean shouldIgnore(Object object) {
        Boolean flag = handlerFlags.get(object);
        if (flag != null) {
            return flag;
        }
        String fullName = object.toString();
        for (String ignore : ignoreConfig) {
            if (fullName.startsWith(ignore)) {
                logger.info("Adding " + fullName + " to OIDC validation ignore list");
                handlerFlags.put(object, true);
                return true;
            }
        }
        logger.info("Adding " + fullName + " to OIDC validation filter list");
        handlerFlags.put(object, false);
        return false;
    }
}
