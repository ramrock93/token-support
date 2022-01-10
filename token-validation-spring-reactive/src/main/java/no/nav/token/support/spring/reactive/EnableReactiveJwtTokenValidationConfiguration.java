package no.nav.token.support.spring.reactive;

import no.nav.security.token.support.core.configuration.MultiIssuerConfiguration;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.security.token.support.core.context.TokenValidationContextHolder;
import no.nav.token.support.spring.reactive.api.EnableReactiveJwtTokenValidation;
import no.nav.token.support.spring.reactive.validation.filter.BearerTokenReactiveClientHttpRequestFilter;
import no.nav.token.support.spring.reactive.validation.filter.JwtTokenReactiveFilter;
import no.nav.token.support.spring.reactive.validation.filter.SpringJwtTokenAnnotationHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import reactor.util.annotation.NonNull;

import java.net.MalformedURLException;
import java.net.URL;

@Configuration
@EnableConfigurationProperties(MultiIssuerProperties.class)
public class EnableReactiveJwtTokenValidationConfiguration implements WebFluxConfigurer, EnvironmentAware, ImportAware {

    private final Logger logger = LoggerFactory.getLogger(EnableReactiveJwtTokenValidationConfiguration.class);

    private Environment env;

    private AnnotationAttributes enableOIDCTokenValidation;

    @Override
    public void setEnvironment(@NonNull Environment env) {
        this.env = env;
    }

    @Override
    public void setImportMetadata(AnnotationMetadata importMetadata) {
        this.enableOIDCTokenValidation = AnnotationAttributes.fromMap(
            importMetadata.getAnnotationAttributes(EnableReactiveJwtTokenValidation.class.getName(), false));
        if (this.enableOIDCTokenValidation == null) {
            throw new IllegalArgumentException(
                "@EnableReactiveJwtTokenValidation is not present on importing class " + importMetadata.getClassName());
        }
    }

    @Bean
    public ServerCodecConfigurer serverCodecConfigurer() {
        return ServerCodecConfigurer.create();
    }

    @Bean
    public ProxyAwareResourceRetriever oidcResourceRetriever() {
        return new ProxyAwareResourceRetriever(getConfiguredProxy(), Boolean.parseBoolean(env.getProperty("https.plaintext", "false")));
    }


    @Bean
    public MultiIssuerConfiguration multiIssuerConfiguration(MultiIssuerProperties issuerProperties, ProxyAwareResourceRetriever resourceRetriever) {
        return new MultiIssuerConfiguration(issuerProperties.getIssuer(), resourceRetriever);
    }

    @Bean
    public TokenValidationContextHolder oidcRequestContextHolder() {
        return new SpringTokenValidationContextHolder();
    }

    @Bean
    public BearerTokenReactiveClientHttpRequestFilter bearerTokenReactiveClientHttpRequestInterceptor(TokenValidationContextHolder tokenValidationContextHolder) {
        logger.info("creating bean for BearerTokenReactiveClientHttpRequestInterceptor");
        return new BearerTokenReactiveClientHttpRequestFilter(tokenValidationContextHolder);
    }

    // @Bean
    // public WebFluxConfigurationSupport webFluxConfigurationSupport() {
    //     return new WebFluxConfigurationSupport();
    // }

    @Bean
    public JwtTokenReactiveFilter getReactiveControllerFilter() {
        logger.debug("registering OIDC token controller handler filter");
        return new JwtTokenReactiveFilter(
            enableOIDCTokenValidation,
            new SpringJwtTokenAnnotationHandler(new SpringTokenValidationContextHolder()));
        // webFluxConfigurationSupport().requestMappingHandlerMapping(exchange -> RequestedContentTypeResolver.MEDIA_TYPE_ALL_LIST));
    }

    private URL getConfiguredProxy() {
        String proxyParameterName = env.getProperty("http.proxy.parametername", "http.proxy");
        String proxyconfig = env.getProperty(proxyParameterName);
        URL proxy = null;
        if (proxyconfig != null && proxyconfig.trim().length() > 0) {
            logger.info("Proxy configuration found [" + proxyParameterName + "] was " + proxyconfig);
            try {
                proxy = new URL(proxyconfig);
            } catch (MalformedURLException e) {
                throw new RuntimeException("config [" + proxyParameterName + "] is misconfigured: " + e, e);
            }
        } else {
            logger.info("No proxy configuration found [" + proxyParameterName + "]");
        }
        return proxy;
    }
}
