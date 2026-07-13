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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.IOUtils;
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
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GenerateJwtPolicyAliasSignatureIsolationTest {

    private static final String MERGED_JKS_STOREPASS = "merged.jks.storepass";
    private static final String MERGED_JKS_KEYPASS = "merged.jks.keypass";
    private static final String MERGED_P12_PASSWORD = "merged.p12.password";
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
        GenerateJwtPolicy.leafCertificates.clear();
        GenerateJwtPolicy.leafCertificatesSha256.clear();
    }

    @AfterEach
    void cleanup() {
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
        GenerateJwtPolicy.leafCertificatesSha256.clear();
    }

    @Test
    void shouldVerifySignatureWithOwnAliasKey_andFailWithOtherAliasKey_jks() throws Exception {
        Path keystore = buildTwoAliasKeystore("JKS", ".jks", MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);

        GenerateJwtPolicyConfiguration configA = jksConfig(keystore, ALIAS_A, MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);
        GenerateJwtPolicyConfiguration configB = jksConfig(keystore, ALIAS_B, MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);

        RSASSAVerifier verifierA = verifierFor(keystore, "JKS", MERGED_JKS_STOREPASS, ALIAS_A);
        RSASSAVerifier verifierB = verifierFor(keystore, "JKS", MERGED_JKS_STOREPASS, ALIAS_B);

        assertThat(certOf(keystore, "JKS", MERGED_JKS_STOREPASS, ALIAS_A))
            .as("pre-condition: the two aliases must carry distinct certificates")
            .isNotEqualTo(certOf(keystore, "JKS", MERGED_JKS_STOREPASS, ALIAS_B));

        SignedJWT jwtA = sign(new GenerateJwtPolicy(configA));
        assertThat(jwtA.verify(verifierA)).as("API-A JWT must verify under its own alias's public key").isTrue();
        assertThat(jwtA.verify(verifierB)).as("API-A JWT must NOT verify under API-B's alias public key").isFalse();

        SignedJWT jwtB = sign(new GenerateJwtPolicy(configB));
        assertThat(jwtB.verify(verifierB)).as("API-B JWT must verify under its own alias's public key").isTrue();
        assertThat(jwtB.verify(verifierA)).as("API-B JWT must NOT verify under API-A's alias public key").isFalse();
    }

    @Test
    void shouldVerifySignatureWithOwnAliasKey_andFailWithOtherAliasKey_pkcs12() throws Exception {
        Path keystore = buildTwoAliasKeystore("PKCS12", ".p12", MERGED_P12_PASSWORD, MERGED_P12_PASSWORD);

        GenerateJwtPolicyConfiguration configA = pkcs12Config(keystore, ALIAS_A, MERGED_P12_PASSWORD);
        GenerateJwtPolicyConfiguration configB = pkcs12Config(keystore, ALIAS_B, MERGED_P12_PASSWORD);

        RSASSAVerifier verifierA = verifierFor(keystore, "PKCS12", MERGED_P12_PASSWORD, ALIAS_A);
        RSASSAVerifier verifierB = verifierFor(keystore, "PKCS12", MERGED_P12_PASSWORD, ALIAS_B);

        assertThat(certOf(keystore, "PKCS12", MERGED_P12_PASSWORD, ALIAS_A))
            .as("pre-condition: the two aliases must carry distinct certificates")
            .isNotEqualTo(certOf(keystore, "PKCS12", MERGED_P12_PASSWORD, ALIAS_B));

        SignedJWT jwtA = sign(new GenerateJwtPolicy(configA));
        assertThat(jwtA.verify(verifierA)).as("API-A (PKCS12) JWT must verify under its own alias's public key").isTrue();
        assertThat(jwtA.verify(verifierB)).as("API-A (PKCS12) JWT must NOT verify under API-B's alias public key").isFalse();

        SignedJWT jwtB = sign(new GenerateJwtPolicy(configB));
        assertThat(jwtB.verify(verifierB)).as("API-B (PKCS12) JWT must verify under its own alias's public key").isTrue();
        assertThat(jwtB.verify(verifierA)).as("API-B (PKCS12) JWT must NOT verify under API-A's alias public key").isFalse();
    }

    @Test
    void shouldIsolateAliasSigners_whenApiBIsSeededBeforeApiA() throws Exception {
        Path keystore = buildTwoAliasKeystore("JKS", ".jks", MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);

        GenerateJwtPolicyConfiguration configA = jksConfig(keystore, ALIAS_A, MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);
        GenerateJwtPolicyConfiguration configB = jksConfig(keystore, ALIAS_B, MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);

        RSASSAVerifier verifierA = verifierFor(keystore, "JKS", MERGED_JKS_STOREPASS, ALIAS_A);
        RSASSAVerifier verifierB = verifierFor(keystore, "JKS", MERGED_JKS_STOREPASS, ALIAS_B);

        SignedJWT jwtB = sign(new GenerateJwtPolicy(configB));
        assertThat(jwtB.verify(verifierB)).as("API-B (seeded first) JWT must verify under its own alias's public key").isTrue();
        assertThat(jwtB.verify(verifierA)).as("API-B (seeded first) JWT must NOT verify under API-A's alias public key").isFalse();

        SignedJWT jwtA = sign(new GenerateJwtPolicy(configA));
        assertThat(jwtA.verify(verifierA))
            .as("API-A (seeded second, cache already warm from API-B) JWT must verify under its own alias's public key")
            .isTrue();
        assertThat(jwtA.verify(verifierB)).as("API-A (seeded second) JWT must NOT verify under API-B's alias public key").isFalse();
    }

    @Test
    void shouldReuseCachedSignerAndCertChain_whenTwoPoliciesShareIdenticalConfiguration() throws Exception {
        Path keystore = buildTwoAliasKeystore("JKS", ".jks", MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);

        GenerateJwtPolicyConfiguration configA = jksConfig(keystore, ALIAS_A, MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);
        GenerateJwtPolicyConfiguration configB = jksConfig(keystore, ALIAS_A, MERGED_JKS_STOREPASS, MERGED_JKS_KEYPASS);

        sign(new GenerateJwtPolicy(configA));
        assertThat(GenerateJwtPolicy.signers).hasSize(1);
        assertThat(GenerateJwtPolicy.certChains).hasSize(1);
        RSASSASigner cachedSigner = GenerateJwtPolicy.signers.values().iterator().next();
        List<Base64> cachedChain = GenerateJwtPolicy.certChains.values().iterator().next();

        sign(new GenerateJwtPolicy(configB));
        assertThat(GenerateJwtPolicy.signers).as("identical configuration must hit the cache, not add a second signer entry").hasSize(1);
        assertThat(GenerateJwtPolicy.certChains)
            .as("identical configuration must hit the cache, not add a second certificate-chain entry")
            .hasSize(1);
        assertThat(GenerateJwtPolicy.signers.values().iterator().next())
            .as("both policies must resolve to the same cached signer object")
            .isSameAs(cachedSigner);
        assertThat(GenerateJwtPolicy.certChains.values().iterator().next())
            .as("both policies must resolve to the same cached certificate-chain object")
            .isSameAs(cachedChain);
    }

    @Test
    void shouldSignSuccessfully_whenAliasIsNull_inlineResolver() throws Exception {
        String pem = loadResourceAsString("/priv.pem");
        String json = mapper.writeValueAsString(
            mapper.createObjectNode().put("keyResolver", "INLINE").put("signature", "RSA_RS256").put("content", pem)
        );
        GenerateJwtPolicyConfiguration config = mapper.readValue(json, GenerateJwtPolicyConfiguration.class);
        assertThat(config.getAlias()).isNull();

        GenerateJwtPolicy policy = new GenerateJwtPolicy(config);

        SignedJWT firstJwt = sign(policy);
        assertThat(firstJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        SignedJWT secondJwt = sign(policy);
        assertThat(secondJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    @Test
    void shouldSignSuccessfully_whenAliasIsNull_pemResolver() throws Exception {
        String pemPath = new File(GenerateJwtPolicy.class.getResource("/priv.pem").toURI()).getCanonicalPath();
        String json = mapper.writeValueAsString(
            mapper.createObjectNode().put("keyResolver", "PEM").put("signature", "RSA_RS256").put("content", pemPath)
        );
        GenerateJwtPolicyConfiguration config = mapper.readValue(json, GenerateJwtPolicyConfiguration.class);
        assertThat(config.getAlias()).isNull();

        GenerateJwtPolicy policy = new GenerateJwtPolicy(config);

        SignedJWT firstJwt = sign(policy);
        assertThat(firstJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);

        SignedJWT secondJwt = sign(policy);
        assertThat(secondJwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
    }

    private SignedJWT sign(GenerateJwtPolicy policy) throws Exception {
        ExecutionContext ctx = mock(ExecutionContext.class);
        TemplateEngine templateEngine = mock(TemplateEngine.class);
        when(ctx.getTemplateEngine()).thenReturn(templateEngine);
        PolicyChain policyChain = mock(PolicyChain.class);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        policy.onRequest(request, response, ctx, policyChain);
        verify(policyChain).doNext(request, response);
        verify(ctx).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());

        return SignedJWT.parse(jwtCaptor.getValue());
    }

    private GenerateJwtPolicyConfiguration jksConfig(Path keystore, String alias, String storepass, String keypass) throws Exception {
        String json = mapper.writeValueAsString(
            mapper
                .createObjectNode()
                .put("keyResolver", "JKS")
                .put("signature", "RSA_RS256")
                .put("content", keystore.toAbsolutePath().toString())
                .put("alias", alias)
                .put("storepass", storepass)
                .put("keypass", keypass)
        );
        return mapper.readValue(json, GenerateJwtPolicyConfiguration.class);
    }

    private GenerateJwtPolicyConfiguration pkcs12Config(Path keystore, String alias, String storepass) throws Exception {
        String json = mapper.writeValueAsString(
            mapper
                .createObjectNode()
                .put("keyResolver", "PKCS12")
                .put("signature", "RSA_RS256")
                .put("content", keystore.toAbsolutePath().toString())
                .put("alias", alias)
                .put("storepass", storepass)
        );
        return mapper.readValue(json, GenerateJwtPolicyConfiguration.class);
    }

    private RSASSAVerifier verifierFor(Path keystorePath, String storeType, String storepass, String alias) throws Exception {
        Certificate cert = certOf(keystorePath, storeType, storepass, alias);
        return new RSASSAVerifier((RSAPublicKey) cert.getPublicKey());
    }

    private Certificate certOf(Path keystorePath, String storeType, String storepass, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(storeType);
        try (InputStream in = Files.newInputStream(keystorePath)) {
            keyStore.load(in, storepass.toCharArray());
        }
        return keyStore.getCertificateChain(alias)[0];
    }

    private Path buildTwoAliasKeystore(String storeType, String suffix, String storepass, String keypass) throws Exception {
        KeyStore merged = KeyStore.getInstance(storeType);
        merged.load(null, null);

        merged.setEntry(
            ALIAS_A,
            privateKeyEntry("/graviteeio-chain.jks", "chain.my.storepass", "leaf", "chain.my.keypass"),
            new KeyStore.PasswordProtection(keypass.toCharArray())
        );
        merged.setEntry(
            ALIAS_B,
            privateKeyEntry("/graviteeio.jks", "graviteeio.my.storepass", "graviteeio", "graviteeio.my.keypass"),
            new KeyStore.PasswordProtection(keypass.toCharArray())
        );

        Path target = Files.createTempFile("alias-isolation-", suffix);
        target.toFile().deleteOnExit();
        try (FileOutputStream out = new FileOutputStream(target.toFile())) {
            merged.store(out, storepass.toCharArray());
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

    private String loadResourceAsString(String resource) throws Exception {
        InputStream stream = GenerateJwtPolicy.class.getResourceAsStream(resource);
        return IOUtils.readInputStreamToString(stream, Charset.defaultCharset());
    }
}
