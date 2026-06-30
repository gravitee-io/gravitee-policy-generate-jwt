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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GenerateJwtPolicyCertificateChainContaminationTest {

    @Mock
    private Request request;

    @Mock
    private Response response;

    @Mock
    private PolicyChain policyChain;

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void x5cHeader_shouldNotBeContaminatedAcrossApis() throws Exception {
        GenerateJwtPolicy policyA = new GenerateJwtPolicy(newJksConfig());
        GenerateJwtPolicy policyB = new GenerateJwtPolicy(newPkcs12Config());

        List<Base64> x5cA1 = extractX5c(policyA);
        List<Base64> x5cB = extractX5c(policyB);

        assertThat(x5cA1).as("pre-condition: JKS and PKCS12 keystores must carry distinct certs").isNotEqualTo(x5cB);

        Base64 expectedLeaf = leafCertFromKeystore("JKS", "/graviteeio.jks", "graviteeio", "graviteeio.my.storepass");
        assertThat(x5cA1.get(0)).as("API-A x5c leaf must match the certificate loaded from graviteeio.jks").isEqualTo(expectedLeaf);

        List<Base64> x5cA2 = extractX5c(policyA);
        assertThat(x5cA2).as("API-A x5c must remain stable after API-B initialises").isEqualTo(x5cA1);
    }

    @Test
    void x5cHeader_forPkcs12Resolver_shouldMatchKeystoreLeafCertificate() throws Exception {
        GenerateJwtPolicy policy = new GenerateJwtPolicy(newPkcs12Config());

        List<Base64> x5c = extractX5c(policy);

        Base64 expectedLeaf = leafCertFromKeystore("PKCS12", "/graviteeio.p12", "graviteeio", "graviteeio.my.storepass");
        assertThat(x5c.get(0)).as("PKCS12 x5c leaf must match the certificate loaded from graviteeio.p12").isEqualTo(expectedLeaf);
    }

    private List<Base64> extractX5c(GenerateJwtPolicy policy) throws Exception {
        ExecutionContext ctx = mock(ExecutionContext.class);
        TemplateEngine templateEngine = mock(TemplateEngine.class);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        policy.onRequest(request, response, ctx, policyChain);
        verify(ctx).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());

        return SignedJWT.parse(jwtCaptor.getValue()).getHeader().getX509CertChain();
    }

    private Base64 leafCertFromKeystore(String type, String resource, String alias, String storepass) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(type);
        try (InputStream in = GenerateJwtPolicy.class.getResourceAsStream(resource)) {
            keyStore.load(in, storepass.toCharArray());
        }
        Certificate leaf = keyStore.getCertificateChain(alias)[0];
        return Base64.encode(leaf.getEncoded());
    }

    private GenerateJwtPolicyConfiguration newJksConfig() throws Exception {
        GenerateJwtPolicyConfiguration config = mock(GenerateJwtPolicyConfiguration.class);
        when(config.getKeyResolver()).thenReturn(KeyResolver.JKS);
        when(config.getAlias()).thenReturn("graviteeio");
        when(config.getStorepass()).thenReturn("graviteeio.my.storepass");
        when(config.getKeypass()).thenReturn("graviteeio.my.keypass");
        when(config.getContent()).thenReturn(uniqueCopy("/graviteeio.jks", ".jks"));
        when(config.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        return config;
    }

    private GenerateJwtPolicyConfiguration newPkcs12Config() throws Exception {
        GenerateJwtPolicyConfiguration config = mock(GenerateJwtPolicyConfiguration.class);
        when(config.getKeyResolver()).thenReturn(KeyResolver.PKCS12);
        when(config.getAlias()).thenReturn("graviteeio");
        when(config.getStorepass()).thenReturn("graviteeio.my.storepass");
        when(config.getContent()).thenReturn(uniqueCopy("/graviteeio.p12", ".p12"));
        when(config.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        return config;
    }

    // No static-cache clear needed: routing content through uniqueCopy() gives every config a
    // fresh randomized cache key, so a test can never collide with another test's signer-cache entry.
    private String uniqueCopy(String resource, String suffix) throws Exception {
        Path source = new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath();
        Path target = Files.createTempFile("contamination-", suffix);
        target.toFile().deleteOnExit();
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        return target.toAbsolutePath().toString();
    }
}
