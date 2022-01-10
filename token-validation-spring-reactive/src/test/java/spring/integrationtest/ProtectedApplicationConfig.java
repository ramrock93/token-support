package spring.integrationtest;

import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever;
import no.nav.token.support.spring.reactive.MultiIssuerProperties;
import no.nav.token.support.spring.reactive.api.EnableReactiveJwtTokenValidation;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.DependsOn;
import org.springframework.context.annotation.Primary;

import java.io.IOException;

@EnableReactiveJwtTokenValidation
@EnableConfigurationProperties(MultiIssuerProperties.class)
@Configuration
public class ProtectedApplicationConfig {

   @Bean
   @Primary
   @DependsOn("mockOAuth2Server")
   public ProxyAwareResourceRetriever oidcResourceRetriever() {
        return new ProxyAwareResourceRetriever();
    }

    @Bean
    public MockOAuth2Server mockOAuth2Server() throws IOException {
        MockOAuth2Server mockOAuth2Server = new MockOAuth2Server();
        mockOAuth2Server.start(1111);
        return mockOAuth2Server;
    }
}
