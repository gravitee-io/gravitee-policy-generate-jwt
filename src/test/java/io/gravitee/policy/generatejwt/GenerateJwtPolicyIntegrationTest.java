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
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
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
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@GatewayTest
class GenerateJwtPolicyIntegrationTest extends AbstractPolicyTest<GenerateJwtPolicy, GenerateJwtPolicyConfiguration> {

    private static final String PEM_WITH_CERT = "/priv-with-cert.pem";

    // Independently computed via:
    //   openssl x509 -in src/test/resources/priv-with-cert.pem -outform DER \
    //     | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    private static final String PINNED_PEM_WITH_CERT_X5T_S256 = "0_FPOwfNYqE3sstWkE7Lb0unsI8sd1qW4pq8M32oVHI";

    @Override
    public void configurePolicies(Map<String, PolicyPlugin> policies) {
        super.configurePolicies(policies);
        policies.put("jwt-attributes-to-headers", PolicyBuilder.build("jwt-attributes-to-headers", JwtAttributeToHeaderPolicy.class));
    }

    // Cache-hit reuse is intentionally not exercised at this gateway level — see GenerateJwtPolicyAliasSignatureIsolationTest, GenerateJwtPolicyX5tThumbprintTest, and GenerateJwtPolicyX5tS256ThumbprintTest for that coverage; caches are cleared every test method here to avoid cross-test static-map pollution.
    @BeforeEach
    void clearStaticCaches() {
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
        GenerateJwtPolicy.leafCertificatesSha256.clear();
    }

    @AfterEach
    void clearStaticCachesAfter() {
        clearStaticCaches();
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

    @Test
    @DisplayName("Should generate an RS256 JWT carrying the x5t#S256 leaf thumbprint and no x5c/x5t members")
    @DeployApi("/apis/generate-jwt-x5t-s256.json")
    void shouldGenerateJWTWithX5tS256Thumbprint(HttpClient httpClient) throws Exception {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        String generatedJwt = generateAndCapture(httpClient, "/test-jwt-x5t-s256");
        SignedJWT signedJWT = SignedJWT.parse(generatedJwt);

        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(signedJWT.verify(new RSASSAVerifier(leafPublicKey()))).isTrue();

        Map<String, Object> rawHeader = decodeRawHeader(generatedJwt);
        assertThat(rawHeader).containsEntry("x5t#S256", PINNED_PEM_WITH_CERT_X5T_S256).doesNotContainKey("x5c").doesNotContainKey("x5t");
    }

    @Test
    @DisplayName("Should generate an RS256 JWT carrying the x5c leaf certificate chain and no x5t/x5t#S256 members")
    @DeployApi("/apis/generate-jwt-x5c.json")
    void shouldGenerateJWTWithX5cCertificateChain(HttpClient httpClient) throws Exception {
        wiremock.stubFor(get("/endpoint").willReturn(ok()));

        String generatedJwt = generateAndCapture(httpClient, "/test-jwt-x5c");
        SignedJWT signedJWT = SignedJWT.parse(generatedJwt);

        assertThat(signedJWT.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        String expectedLeafBase64Der = com.nimbusds.jose.util.Base64.encode(leafCertificate().getEncoded()).toString();
        Map<String, Object> rawHeader = decodeRawHeader(generatedJwt);
        assertThat(rawHeader).containsKey("x5c").doesNotContainKey("x5t").doesNotContainKey("x5t#S256");
        @SuppressWarnings("unchecked")
        List<String> x5c = (List<String>) rawHeader.get("x5c");
        assertThat(x5c).containsExactly(expectedLeafBase64Der);
    }

    private String generateAndCapture(HttpClient httpClient, String contextPath) throws InterruptedException {
        httpClient
            .rxRequest(HttpMethod.GET, contextPath)
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
        return requests.get(0).getHeader(GENERATED_JWT_HEADER_NAME);
    }

    private Map<String, Object> decodeRawHeader(String jwt) throws ParseException {
        String protectedHeader = new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
        return JSONObjectUtils.parse(protectedHeader);
    }

    private X509Certificate leafCertificate() throws Exception {
        try (InputStream in = GenerateJwtPolicy.class.getResourceAsStream(PEM_WITH_CERT)) {
            byte[] pem = in.readAllBytes();
            String certBlock = new String(pem, StandardCharsets.UTF_8);
            int begin = certBlock.indexOf("-----BEGIN CERTIFICATE-----");
            byte[] certBytes = certBlock.substring(begin).getBytes(StandardCharsets.UTF_8);
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(certBytes));
        }
    }

    private RSAPublicKey leafPublicKey() throws Exception {
        return (RSAPublicKey) leafCertificate().getPublicKey();
    }
}
