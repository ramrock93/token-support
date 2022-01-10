package no.nav.token.support.spring.reactive.validation.filter;
/*
 * THIS CODE IS PROVIDED *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS
 * OF ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION
 * ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A
 * PARTICULAR PURPOSE, MERCHANTABILITY OR NON-INFRINGEMENT.
 */

import no.nav.security.token.support.core.JwtTokenConstants;
import no.nav.security.token.support.core.context.TokenValidationContext;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

public class BearerTokenReactiveClientHttpRequestFilter implements ExchangeFilterFunction {

    private final Logger logger = LoggerFactory.getLogger(BearerTokenReactiveClientHttpRequestFilter.class);

    private final TokenValidationContextHolder contextHolder;

    public BearerTokenReactiveClientHttpRequestFilter(TokenValidationContextHolder contextHolder) {
        this.contextHolder = contextHolder;
    }

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction nextFilter) {
        TokenValidationContext context = contextHolder.getTokenValidationContext();
        if (context != null && context.hasValidToken()) {
            StringBuilder headerValue = new StringBuilder();
            boolean first = true;
            for (String issuer : context.getIssuers()) {
                logger.debug("adding token for issuer {}", issuer);
                if (!first) {
                    headerValue.append(",");
                }
                headerValue.append("Bearer " + context.getJwtToken(issuer).getTokenAsString());
                first = false;
            }
            request.headers().add(JwtTokenConstants.AUTHORIZATION_HEADER, headerValue.toString());
        } else {
            logger.debug("no tokens found, nothing added to request");
        }
        return nextFilter.exchange(request);
    }
}
