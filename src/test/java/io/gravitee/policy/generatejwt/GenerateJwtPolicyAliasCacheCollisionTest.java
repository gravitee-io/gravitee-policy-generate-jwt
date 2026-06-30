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
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
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
class GenerateJwtPolicyAliasCacheCollisionTest {

    private static final String MERGED_STOREPASS = "merged.storepass";
    private static final String MERGED_KEYPASS = "merged.keypass";
    private static final String ALIAS_A = "leaf";
    private static final String ALIAS_B = "graviteeio";

    @Mock
    private Request request;

    @Mock
    private Response response;

    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void init() {
        MockitoAnnotations.openMocks(this);
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
    }

    @Test
    void x5c_shouldReflectEachConfigurationsOwnAlias_whenTwoApisShareTheSameKeystoreFile() throws Exception {
        Path mergedKeystore = buildTwoAliasKeystore();
        String sharedContentPath = mergedKeystore.toAbsolutePath().toString();

        GenerateJwtPolicyConfiguration configA = deserializeConfig(sharedContentPath, ALIAS_A);
        GenerateJwtPolicyConfiguration configB = deserializeConfig(sharedContentPath, ALIAS_B);

        Base64 expectedLeafA = leafCertOf(mergedKeystore, ALIAS_A);
        Base64 expectedLeafB = leafCertOf(mergedKeystore, ALIAS_B);
        assertThat(expectedLeafA).as("pre-condition: the two aliases must carry distinct certificates").isNotEqualTo(expectedLeafB);

        List<Base64> x5cA = extractX5c(new GenerateJwtPolicy(configA));
        assertThat(x5cA.get(0)).as("API-A x5c leaf must match its own alias's certificate").isEqualTo(expectedLeafA);

        List<Base64> x5cB = extractX5c(new GenerateJwtPolicy(configB));
        assertThat(x5cB.get(0))
            .as("API-B (same keystore file, different alias) x5c leaf must match ITS OWN alias's certificate, not API-A's")
            .isEqualTo(expectedLeafB);
    }

    private GenerateJwtPolicyConfiguration deserializeConfig(String contentPath, String alias) throws Exception {
        String json = mapper.writeValueAsString(
            mapper
                .createObjectNode()
                .put("keyResolver", "JKS")
                .put("signature", "RSA_RS256")
                .put("content", contentPath)
                .put("alias", alias)
                .put("storepass", MERGED_STOREPASS)
                .put("keypass", MERGED_KEYPASS)
                .put("x509CertificateChain", "X5C")
        );
        return mapper.readValue(json, GenerateJwtPolicyConfiguration.class);
    }

    private List<Base64> extractX5c(GenerateJwtPolicy policy) throws Exception {
        ExecutionContext ctx = mock(ExecutionContext.class);
        TemplateEngine templateEngine = mock(TemplateEngine.class);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        PolicyChain policyChain = mock(PolicyChain.class);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        policy.onRequest(request, response, ctx, policyChain);
        verify(policyChain).doNext(request, response);
        verify(ctx).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());

        return SignedJWT.parse(jwtCaptor.getValue()).getHeader().getX509CertChain();
    }

    private Base64 leafCertOf(Path keystorePath, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(keystorePath)) {
            keyStore.load(in, MERGED_STOREPASS.toCharArray());
        }
        Certificate leaf = keyStore.getCertificateChain(alias)[0];
        return Base64.encode(leaf.getEncoded());
    }

    private Path buildTwoAliasKeystore() throws Exception {
        KeyStore merged = KeyStore.getInstance("JKS");
        merged.load(null, null);

        merged.setEntry(
            ALIAS_A,
            privateKeyEntry("/graviteeio-chain.jks", "chain.my.storepass", "leaf", "chain.my.keypass"),
            new KeyStore.PasswordProtection(MERGED_KEYPASS.toCharArray())
        );
        merged.setEntry(
            ALIAS_B,
            privateKeyEntry("/graviteeio.jks", "graviteeio.my.storepass", "graviteeio", "graviteeio.my.keypass"),
            new KeyStore.PasswordProtection(MERGED_KEYPASS.toCharArray())
        );

        Path target = Files.createTempFile("alias-collision-", ".jks");
        target.toFile().deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(target.toFile())) {
            merged.store(out, MERGED_STOREPASS.toCharArray());
        }
        return target;
    }

    private KeyStore.PrivateKeyEntry privateKeyEntry(String resource, String storepass, String alias, String keypass) throws Exception {
        KeyStore source = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath())) {
            source.load(in, storepass.toCharArray());
        }
        return (KeyStore.PrivateKeyEntry) source.getEntry(alias, new KeyStore.PasswordProtection(keypass.toCharArray()));
    }
}
