package no.nav.security.token.support.client.core.oauth2;

import com.github.benmanes.caffeine.cache.Cache;
import no.nav.security.token.support.client.core.ClientProperties;
import no.nav.security.token.support.client.core.OAuth2ClientException;
import no.nav.security.token.support.client.core.OAuth2GrantType;
import no.nav.security.token.support.client.core.context.JwtBearerTokenResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

@SuppressWarnings("WeakerAccess")
public class OAuth2AccessTokenService {

    private static final List<OAuth2GrantType> SUPPORTED_GRANT_TYPES = Arrays.asList(
        OAuth2GrantType.JWT_BEARER,
        OAuth2GrantType.CLIENT_CREDENTIALS,
        OAuth2GrantType.TOKEN_EXCHANGE
    );
    private static final Logger log = LoggerFactory.getLogger(OAuth2AccessTokenService.class);

    private Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsGrantCache;
    private Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfGrantCache;
    private Cache<TokenExchangeGrantRequest, OAuth2AccessTokenResponse> exchangeGrantCache;
    private final TokenExchangeClient tokenExchangeClient;
    private final JwtBearerTokenResolver tokenResolver;
    private final OnBehalfOfTokenClient onBehalfOfTokenClient;
    private final ClientCredentialsTokenClient clientCredentialsTokenClient;

    public OAuth2AccessTokenService(JwtBearerTokenResolver tokenResolver,
                                    OnBehalfOfTokenClient onBehalfOfTokenClient,
                                    ClientCredentialsTokenClient clientCredentialsTokenClient,
                                    TokenExchangeClient tokenExchangeClient) {
        this.tokenResolver = tokenResolver;
        this.onBehalfOfTokenClient = onBehalfOfTokenClient;
        this.clientCredentialsTokenClient = clientCredentialsTokenClient;
        this.tokenExchangeClient = tokenExchangeClient;
    }

    private static <T extends AbstractOAuth2GrantRequest> OAuth2AccessTokenResponse getFromCacheIfEnabled(
        T grantRequest,
        Cache<T, OAuth2AccessTokenResponse> cache,
        Function<T, OAuth2AccessTokenResponse> accessTokenResponseClient
    ) {
        if (cache != null) {
            log.debug("cache is enabled so attempt to get from cache or update cache if not present.");
            return cache.get(grantRequest, accessTokenResponseClient);
        } else {
            log.debug("cache is not set, invoke client directly");
            return accessTokenResponseClient.apply(grantRequest);
        }
    }

    @SuppressWarnings("unused")
    public Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> getClientCredentialsGrantCache() {
        return clientCredentialsGrantCache;
    }

    public OAuth2AccessTokenResponse getAccessToken(ClientProperties clientProperties) {
        if (clientProperties == null) {
            throw new OAuth2ClientException("ClientProperties cannot be null");
        }
        log.debug("getting access_token for grant={}", clientProperties.getGrantType());
        if (isGrantType(clientProperties, OAuth2GrantType.JWT_BEARER)) {
            return executeOnBehalfOf(clientProperties);
        } else if (isGrantType(clientProperties, OAuth2GrantType.CLIENT_CREDENTIALS)) {
            return executeClientCredentials(clientProperties);
        } else if (isGrantType(clientProperties, OAuth2GrantType.TOKEN_EXCHANGE)) {
            return executeTokenExchange(clientProperties);
        } else {
            throw new OAuth2ClientException(String.format("invalid grant-type=%s from OAuth2ClientConfig.OAuth2Client" +
                    ". grant-type not in supported grant-types (%s)",
                clientProperties.getGrantType().value(), SUPPORTED_GRANT_TYPES));
        }
    }

    @SuppressWarnings("unused")
    public Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> getOnBehalfOfGrantCache() {
        return onBehalfOfGrantCache;
    }

    public void setOnBehalfOfGrantCache(Cache<OnBehalfOfGrantRequest, OAuth2AccessTokenResponse> onBehalfOfGrantCache) {
        this.onBehalfOfGrantCache = onBehalfOfGrantCache;
    }

    public void setClientCredentialsGrantCache(Cache<ClientCredentialsGrantRequest, OAuth2AccessTokenResponse> clientCredentialsGrantCache) {
        this.clientCredentialsGrantCache = clientCredentialsGrantCache;
    }

    public void setExchangeGrantCache(Cache<TokenExchangeGrantRequest, OAuth2AccessTokenResponse> exchangeGrantCache) {
        this.exchangeGrantCache = exchangeGrantCache;
    }

    public  Cache<TokenExchangeGrantRequest, OAuth2AccessTokenResponse>  getExchangeGrantCache() {
        return exchangeGrantCache;
    }

    private OAuth2AccessTokenResponse executeOnBehalfOf(ClientProperties clientProperties) {
        final var grantRequest = onBehalfOfGrantRequest(clientProperties);
        return getFromCacheIfEnabled(grantRequest, onBehalfOfGrantCache, onBehalfOfTokenClient::getTokenResponse);
    }

    private OAuth2AccessTokenResponse executeTokenExchange(ClientProperties clientProperties) {
        final var grantRequest = tokenExchangeGrantRequest(clientProperties);
        return getFromCacheIfEnabled(grantRequest, exchangeGrantCache, tokenExchangeClient::getTokenResponse);
    }

    private OAuth2AccessTokenResponse executeClientCredentials(ClientProperties clientProperties) {
        final var grantRequest = new ClientCredentialsGrantRequest(clientProperties);
        return getFromCacheIfEnabled(grantRequest, clientCredentialsGrantCache,
            clientCredentialsTokenClient::getTokenResponse);
    }

    private boolean isGrantType(ClientProperties clientProperties,
                                OAuth2GrantType grantType) {
        return Optional.ofNullable(clientProperties)
            .filter(client -> client.getGrantType().equals(grantType))
            .isPresent();
    }

    private TokenExchangeGrantRequest tokenExchangeGrantRequest(ClientProperties clientProperties) {
        return new TokenExchangeGrantRequest(clientProperties, tokenResolver.token()
            .orElseThrow(() -> new OAuth2ClientException("no authenticated jwt token found in validation context, " +
                "cannot do token exchange")));
    }

    private OnBehalfOfGrantRequest onBehalfOfGrantRequest(ClientProperties clientProperties) {
        return new OnBehalfOfGrantRequest(clientProperties, tokenResolver.token()
            .orElseThrow(() -> new OAuth2ClientException("no authenticated jwt token found in validation context, " +
                "cannot do on-behalf-of")));
    }

    @Override
    public String toString() {
        return getClass().getSimpleName() + " [" +
            "                            clientCredentialsGrantCache=" + clientCredentialsGrantCache +
            ",                             onBehalfOfGrantCache=" + onBehalfOfGrantCache +
            ",                             tokenExchangeClient=" + tokenExchangeClient +
            ",                             tokenResolver=" + tokenResolver +
            ",                             onBehalfOfTokenClient=" + onBehalfOfTokenClient +
            ",                             clientCredentialsTokenClient=" + clientCredentialsTokenClient +
            ",                             exchangeGrantCache=" + exchangeGrantCache +
            "]";
    }
}
