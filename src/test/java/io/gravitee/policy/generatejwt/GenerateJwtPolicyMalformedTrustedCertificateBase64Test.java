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

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.reporter.api.http.Metrics;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Regression guard: certificateOnlyPemBlock() decodes a TRUSTED CERTIFICATE
 * block body with Base64.getMimeDecoder().decode() before any validity check. This test uses a
 * body that is genuinely non-base64 text (not merely an invalid-but-decodable payload like the one
 * covered by GenerateJwtPolicyLegacyCertificateLabelTest#rejectsRequest_whenTrustedCertificateBlockBodyIsNotAValidCertificate)
 * to check whether the resulting IllegalArgumentException propagates uncaught out of onRequest.
 */
class GenerateJwtPolicyMalformedTrustedCertificateBase64Test {

    @Mock
    private ExecutionContext executionContext;

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    @Mock
    private TemplateEngine templateEngine;

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
        GenerateJwtPolicy.leafCertificatesSha256.clear();
        when(request.metrics()).thenReturn(Metrics.on(System.currentTimeMillis()).build());
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(anyString())).thenAnswer(invMock -> invMock.getArgument(0));
        when(templateEngine.getValue(anyString(), any())).thenAnswer(invMock -> invMock.getArgument(0));
    }

    @AfterEach
    void tearDown() {
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
        GenerateJwtPolicy.leafCertificatesSha256.clear();
    }

    @Test
    void rejectsRequest_whenTrustedCertificateBlockBodyIsNotBase64AtAll() throws Exception {
        String inlineContent =
            pemEncodePrivateKey(selfSignedKeyPair().getPrivate()) +
            "\n-----BEGIN TRUSTED CERTIFICATE-----\n!!!not-base64!!!\n-----END TRUSTED CERTIFICATE-----\n";

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", inlineContent);
        config.put("x509CertificateChain", "NONE");
        config.put("x509CertSha1Thumbprint", true);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        assertDoesNotThrow(
            () -> new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain),
            "a TRUSTED CERTIFICATE block body that is genuinely non-base64 text must fail closed, not throw uncaught"
        );

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(1)).failWith(captor.capture());
        assertEquals(
            500,
            captor.getValue().statusCode(),
            "a TRUSTED CERTIFICATE block whose body is not base64 at all must fail with HTTP 500, not throw uncaught"
        );
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    private static KeyPair selfSignedKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String pemEncodePrivateKey(java.security.PrivateKey privateKey) {
        return (
            "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(privateKey.getEncoded()) +
            "\n-----END PRIVATE KEY-----\n"
        );
    }
}
