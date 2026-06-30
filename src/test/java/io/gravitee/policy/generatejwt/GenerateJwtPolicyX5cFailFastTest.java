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

import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class GenerateJwtPolicyX5cFailFastTest {

    private static final String HMAC_SECRET_512_BITS = "0123456789012345678901234567890123456789012345678901234567890123";

    @Mock
    private ExecutionContext executionContext;

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    @Mock
    private GenerateJwtPolicyConfiguration configuration;

    @Mock
    private TemplateEngine templateEngine;

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
        when(templateEngine.getValue(anyString(), any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @AfterEach
    void tearDown() {
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
    }

    @ParameterizedTest
    @EnumSource(value = Signature.class, names = { "HMAC_HS256", "HMAC_HS384", "HMAC_HS512" })
    void ignoresX5cCertificateChainAndSignsNormally_whenHmacSignatureConfiguredWithX5cCertificateChain(Signature signature)
        throws Exception {
        when(configuration.getSignature()).thenReturn(signature);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getContent()).thenReturn(HMAC_SECRET_512_BITS);
        when(configuration.getSecretBase64Encoded()).thenReturn(false);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain).doNext(request, response);
        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
        SignedJWT signedJWT = SignedJWT.parse(jwtCaptor.getValue());
        assertNull(signedJWT.getHeader().getX509CertChain(), "an HMAC signature carries no certificate, so x5c must be silently ignored");
    }
}
