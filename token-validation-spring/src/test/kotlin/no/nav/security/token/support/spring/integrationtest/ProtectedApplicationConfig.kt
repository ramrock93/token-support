package no.nav.security.token.support.spring.integrationtest

import no.nav.security.mock.oauth2.MockOAuth2Server
import no.nav.security.token.support.core.configuration.ProxyAwareResourceRetriever
import no.nav.security.token.support.spring.MultiIssuerProperties
import no.nav.security.token.support.spring.api.EnableJwtTokenValidation
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.DependsOn
import org.springframework.context.annotation.Primary
import java.io.IOException

@EnableJwtTokenValidation
@EnableConfigurationProperties(MultiIssuerProperties::class)
@Configuration
class ProtectedApplicationConfig {
    @Bean
    @Primary
    @DependsOn("mockOAuth2Server")
    fun oidcResourceRetriever() = ProxyAwareResourceRetriever()


    @Bean
    @Throws(IOException::class)
    fun mockOAuth2Server(): MockOAuth2Server {
        val mockOAuth2Server = MockOAuth2Server()
        mockOAuth2Server.start(1111)
        return mockOAuth2Server
    }
}