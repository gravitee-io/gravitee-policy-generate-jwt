/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.generatejwt;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.gravitee.policy.generatejwt.JwtAttributeToHeaderPolicy.GENERATED_JWT_HEADER_NAME;
import static org.assertj.core.api.Assertions.assertThat;

import com.github.tomakehurst.wiremock.verification.LoggedRequest;
import com.google.common.primitives.Bytes;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.apim.gateway.tests.sdk.AbstractPolicyTest;
import io.gravitee.apim.gateway.tests.sdk.annotations.DeployApi;
import io.gravitee.apim.gateway.tests.sdk.annotations.GatewayTest;
import io.gravitee.apim.gateway.tests.sdk.policy.PolicyBuilder;
import io.gravitee.plugin.policy.PolicyPlugin;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.vertx.core.http.HttpMethod;
import io.vertx.rxjava3.core.http.HttpClient;
import io.vertx.rxjava3.core.http.HttpClientRequest;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@GatewayTest
class GenerateJwtPolicyIntegrationTest extends AbstractPolicyTest<GenerateJwtPolicy, GenerateJwtPolicyConfiguration> {

    @Override
    public void configurePolicies(Map<String, PolicyPlugin> policies) {
        super.configurePolicies(policies);
        policies.put("jwt-attributes-to-headers", PolicyBuilder.build("jwt-attributes-to-headers", JwtAttributeToHeaderPolicy.class));
    }

    @Test
    @DisplayName("Should generate a JWT token with custom claims")
    @DeployApi("/apis/generate-jwt-custom-claims.json")
    void shouldGenerateJWTWithCustomClaims(HttpClient httpClient) throws InterruptedException, ParseException {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        httpClient
            .rxRequest(HttpMethod.GET, "/test")
            .flatMap(HttpClientRequest::rxSend)
            .test()
            .await()
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return true;
            })
            .assertNoErrors();

        List<LoggedRequest> requests = wiremock.findRequestsMatching(getRequestedFor(urlPathEqualTo("/endpoint")).build()).getRequests();
        assertThat(requests).hasSize(1);
        String generatedJwt = requests.get(0).getHeader(GENERATED_JWT_HEADER_NAME);
        SignedJWT signedJWT = SignedJWT.parse(generatedJwt);
        JWSHeader jwsHeader = signedJWT.getHeader();
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        assertThat(jwsHeader.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
        assertThat(jwsHeader.getKeyID()).isEqualTo("my-kid");
        assertThat(claimsSet.getJWTID()).isEqualTo("817c6cfa-6ae6-446e-a631-5ded215b404b");
        assertThat(claimsSet.getStringClaim("claim1")).isEqualTo("claim1-value");
        assertThat(claimsSet.getClaim("claim2")).isEqualTo("/test");
    }

    @Test
    @DisplayName("Should generate a JWT token with secret base64 encoded")
    @DeployApi("/apis/generate-jwt-secret-base64.json")
    void shouldGenerateJWTWithSecretBase64Encoded(HttpClient httpClient) throws InterruptedException, ParseException, JOSEException {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        httpClient
            .rxRequest(HttpMethod.GET, "/test-jwt-secret-base64")
            .flatMap(HttpClientRequest::rxSend)
            .test()
            .await()
            .assertComplete()
            .assertValue(response -> {
                assertThat(response.statusCode()).isEqualTo(200);
                return true;
            })
            .assertNoErrors();

        List<LoggedRequest> requests = wiremock.findRequestsMatching(getRequestedFor(urlPathEqualTo("/endpoint")).build()).getRequests();
        assertThat(requests).hasSize(1);
        String generatedJwt = requests.get(0).getHeader(GENERATED_JWT_HEADER_NAME);
        SignedJWT signedJWT = SignedJWT.parse(generatedJwt);
        JWSHeader jwsHeader = signedJWT.getHeader();
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        JWSVerifier verifier = new MACVerifier("I'm a valid Base64 key with at least 256 bits\n");
        assertThat(signedJWT.verify(verifier)).isTrue();

        assertThat(jwsHeader.getAlgorithm()).isEqualTo(JWSAlgorithm.HS256);
    }
}
