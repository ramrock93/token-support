package no.nav.security.oidc.jaxrs;

import no.nav.security.oidc.OIDCConstants;
import no.nav.security.oidc.test.support.JwtTokenGenerator;
import no.nav.security.oidc.test.support.spring.TokenGeneratorConfiguration;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.core.Is.is;

@ActiveProfiles("invalid")
@RunWith(SpringRunner.class)
@DirtiesContext
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        classes = Config.class)
public class ServerFilterProtectedMethodUnknownIssuerTest {

    @Value("${local.server.port}")
    private int port;

    private Invocation.Builder requestWithInvalidClaimsToken(String path) {
        return ClientBuilder.newClient().target("http://localhost:" + port)
                .path(path)
                .request()
                .header(OIDCConstants.AUTHORIZATION_HEADER, "Bearer " + JwtTokenGenerator.createSignedJWT("12345678911").serialize());
    }

    @Test
    public void that_unprotected_returns_ok_with_invalid_token() {

        Response response = requestWithInvalidClaimsToken("unprotected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_returns_200_with_any_token() {

        Response response = requestWithInvalidClaimsToken("protected").get();

        assertThat(response.getStatus(), is(equalTo(200)));
    }

    @Test
    public void that_protected_with_claims_returns_401_with_invalid_token() {

        Response response = requestWithInvalidClaimsToken("protected/with/claims").get();

        assertThat(response.getStatus(), is(equalTo(401)));
    }

}
