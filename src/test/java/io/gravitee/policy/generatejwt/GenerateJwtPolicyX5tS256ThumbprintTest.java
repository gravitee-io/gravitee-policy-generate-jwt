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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.reporter.api.http.Metrics;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Regression tests for the x5t#S256 (SHA-256 certificate thumbprint) JWS header parameter.
 *
 * @author GraviteeSource Team
 */
class GenerateJwtPolicyX5tS256ThumbprintTest {

    private static final String GRAVITEEIO_JKS = "/graviteeio.jks";
    private static final String GRAVITEEIO_JKS_STOREPASS = "graviteeio.my.storepass";
    private static final String GRAVITEEIO_JKS_KEYPASS = "graviteeio.my.keypass";
    private static final String GRAVITEEIO_JKS_ALIAS = "graviteeio";

    // Computed independently of production, via:
    //   keytool -exportcert -alias graviteeio -keystore src/test/resources/graviteeio.jks -storepass graviteeio.my.storepass \
    //     | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    private static final String PINNED_GRAVITEEIO_JKS_X5T_S256 = "riIh3M8_l-Sk3Kb51IW2AY_W2RDr-k-KXkUQGKwHiMY";

    private static final String CHAIN_JKS = "/graviteeio-chain.jks";
    private static final String CHAIN_JKS_STOREPASS = "chain.my.storepass";
    private static final String CHAIN_JKS_KEYPASS = "chain.my.keypass";
    private static final String CHAIN_JKS_ALIAS = "leaf";

    // Same command as PINNED_GRAVITEEIO_JKS_X5T_S256, against graviteeio-chain.jks alias "leaf" / storepass "chain.my.storepass".
    private static final String PINNED_CHAIN_JKS_X5T_S256 = "Dm_SKu-Hwzh5zyw-23JEV9CvnbbFk_gglgGvPQfVxT0";

    private static final String GRAVITEEIO_P12 = "/graviteeio.p12";
    private static final String GRAVITEEIO_P12_STOREPASS = "graviteeio.my.storepass";
    private static final String GRAVITEEIO_P12_ALIAS = "graviteeio";

    // Same command as PINNED_GRAVITEEIO_JKS_X5T_S256, but add "-storetype PKCS12" against graviteeio.p12.
    private static final String PINNED_GRAVITEEIO_P12_X5T_S256 = "n5duAZhFJFeAB3gRvQrNKUsYg63UA3nvffKy1wWsaDo";

    private static final String PEM_WITH_CERT = "/priv-with-cert.pem";

    // Computed independently of production, via:
    //   openssl x509 -in src/test/resources/priv-with-cert.pem -outform DER \
    //     | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    private static final String PINNED_PEM_WITH_CERT_X5T_S256 = "0_FPOwfNYqE3sstWkE7Lb0unsI8sd1qW4pq8M32oVHI";

    // Same command with -sha1 instead of -sha256.
    private static final String PINNED_PEM_WITH_CERT_X5T = "1VIruVLp9rHaINhtafJpVjintZw";

    private static final String PEM_WITH_CA_FIRST_CHAIN = "/priv-with-chain-ca-first.pem";

    // priv-with-chain-ca-first.pem holds two certificates (CA first, signing/leaf second). Extract
    // just the second (non-self-signed) certificate block into its own file, then run the same
    // command as PINNED_PEM_WITH_CERT_X5T_S256 against that file.
    private static final String PINNED_PEM_WITH_CA_FIRST_CHAIN_X5T_S256 = "FSfIvgYGXCiKU2mtbeMdtCXRf6bSQ5X5_alEaP3k2JU";

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

    @ParameterizedTest(name = "{0}")
    @MethodSource("resolverFixtures")
    void x5tS256IsBase64UrlOfSha256OfLeafDer_acrossAllResolvers(String resolverName, ResolverSetup setup) throws Exception {
        Fixture fixture = setup.apply(this);

        Map<String, Object> header = decodeHeader(generateJwt(fixture.configuration()));

        assertTrue(header.containsKey("x5t#S256"), resolverName + " resolver must emit x5t#S256 when the SHA-256 toggle is enabled");

        String x5tS256 = (String) header.get("x5t#S256");
        assertEquals(fixture.expectedX5tS256(), x5tS256, resolverName + " x5t#S256 must equal base64url(SHA-256(DER(leaf cert)))");

        assertEquals(43, x5tS256.length(), "32-byte SHA-256 digest encodes to 43 base64url chars");
        assertTrue(x5tS256.matches("^[A-Za-z0-9_-]{43}$"), "x5t#S256 must match the base64url alphabet");
        assertFalse(x5tS256.contains("="), "x5t#S256 must have no '=' padding");
        assertFalse(x5tS256.contains("+"), "x5t#S256 must not contain '+'");
        assertFalse(x5tS256.contains("/"), "x5t#S256 must not contain '/'");
    }

    @Test
    void x5tS256ComputedFromLeafOnly_whenInlineContentListsCaBeforeLeaf() throws Exception {
        String pem = fixtureText(PEM_WITH_CA_FIRST_CHAIN);
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of("signature", "RSA_RS256", "keyResolver", "INLINE", "content", pem, "x509CertSha256Thumbprint", true)
        );

        Map<String, Object> header = decodeHeader(generateJwt(configuration));

        String x5tS256 = (String) header.get("x5t#S256");

        assertEquals(
            PINNED_PEM_WITH_CA_FIRST_CHAIN_X5T_S256,
            x5tS256,
            "x5t#S256 must equal the SHA-256 thumbprint of the signing (leaf) certificate even when a CA precedes it in the raw content"
        );
    }

    @Test
    void x5tS256ComputedFromLeafOnly_whenKeystoreChainHasCaAfterLeaf() throws Exception {
        String keystorePath = uniqueCopy(CHAIN_JKS, ".jks");
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "JKS",
                "content",
                keystorePath,
                "alias",
                CHAIN_JKS_ALIAS,
                "storepass",
                CHAIN_JKS_STOREPASS,
                "keypass",
                CHAIN_JKS_KEYPASS,
                "x509CertSha256Thumbprint",
                true
            )
        );

        String x5tS256 = (String) decodeHeader(generateJwt(configuration)).get("x5t#S256");

        Certificate[] chain = loadKeystoreChain(keystorePath, CHAIN_JKS_STOREPASS, CHAIN_JKS_ALIAS);
        assertTrue(chain.length >= 2, "fixture must supply a multi-entry chain (leaf + CA)");

        assertEquals(PINNED_CHAIN_JKS_X5T_S256, x5tS256, "keystore x5t#S256 must equal the SHA-256 thumbprint of chain[0] (the leaf)");
    }

    @Test
    void x5tS256Backfilled_whenToggleEnabledAfterSignerCachedWithSha1Only() throws Exception {
        String pem = fixtureText(PEM_WITH_CERT);

        GenerateJwtPolicyConfiguration sha1Only = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "INLINE",
                "content",
                pem,
                "x509CertSha1Thumbprint",
                true,
                "x509CertSha256Thumbprint",
                false
            )
        );
        Map<String, Object> warmupHeader = decodeHeader(generateJwt(sha1Only));
        assertTrue(warmupHeader.containsKey("x5t"), "pre-condition: the SHA-1-only warm-up must warm the SHA-1 leaf map");
        assertFalse(warmupHeader.containsKey("x5t#S256"), "pre-condition: the SHA-1-only warm-up must leave the SHA-256 leaf map cold");

        clearInvocations(policyChain, executionContext);

        GenerateJwtPolicyConfiguration sha256On = config(
            Map.of("signature", "RSA_RS256", "keyResolver", "INLINE", "content", pem, "x509CertSha256Thumbprint", true)
        );
        String x5tS256 = (String) decodeHeader(generateJwt(sha256On)).get("x5t#S256");

        assertEquals(
            PINNED_PEM_WITH_CERT_X5T_S256,
            x5tS256,
            "the SHA-256 leaf thumbprint must be backfilled and emitted on a signer cache hit even when only the SHA-1 toggle was resolved on the first load"
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cacheHitFixtures")
    void x5tS256RemainsCorrect_onSignerCacheHit(String resolverName, ResolverSetup setup) throws Exception {
        Fixture fixture = setup.apply(this);
        GenerateJwtPolicy policy = new GenerateJwtPolicy(fixture.configuration());

        policy.onRequest(request, response, executionContext, policyChain);
        policy.onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(2)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());

        String expected = fixture.expectedX5tS256();
        for (Object jwt : captor.getAllValues()) {
            Map<String, Object> header = decodeHeader((String) jwt);
            assertEquals(
                expected,
                header.get("x5t#S256"),
                resolverName + " x5t#S256 must remain correct whether the signer came from a cache miss or a cache hit"
            );
        }
    }

    static Stream<Arguments> cacheHitFixtures() {
        return Stream.of(
            Arguments.of("INLINE", (ResolverSetup) GenerateJwtPolicyX5tS256ThumbprintTest::inlineFixture),
            Arguments.of("JKS", (ResolverSetup) GenerateJwtPolicyX5tS256ThumbprintTest::jksFixture)
        );
    }

    @Test
    void x5tS256DoesNotLeakBetweenDifferentCachedCertificates() throws Exception {
        String chainKeystorePath = uniqueCopy(CHAIN_JKS, ".jks");
        GenerateJwtPolicyConfiguration otherApiConfig = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "JKS",
                "content",
                chainKeystorePath,
                "alias",
                CHAIN_JKS_ALIAS,
                "storepass",
                CHAIN_JKS_STOREPASS,
                "keypass",
                CHAIN_JKS_KEYPASS,
                "x509CertSha256Thumbprint",
                true
            )
        );
        String otherApiX5tS256 = (String) decodeHeader(generateJwt(otherApiConfig)).get("x5t#S256");

        clearInvocations(policyChain, executionContext);

        String thisKeystorePath = uniqueCopy(GRAVITEEIO_JKS, ".jks");
        GenerateJwtPolicyConfiguration thisApiConfig = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "JKS",
                "content",
                thisKeystorePath,
                "alias",
                GRAVITEEIO_JKS_ALIAS,
                "storepass",
                GRAVITEEIO_JKS_STOREPASS,
                "keypass",
                GRAVITEEIO_JKS_KEYPASS,
                "x509CertSha256Thumbprint",
                true
            )
        );
        String thisApiX5tS256 = (String) decodeHeader(generateJwt(thisApiConfig)).get("x5t#S256");

        assertEquals(PINNED_CHAIN_JKS_X5T_S256, otherApiX5tS256, "the first API's x5t#S256 must be its own leaf thumbprint");
        assertEquals(
            PINNED_GRAVITEEIO_JKS_X5T_S256,
            thisApiX5tS256,
            "the second API's x5t#S256 must be its own leaf thumbprint, not leaked from the first API's cached SHA-256 entry"
        );
    }

    @ParameterizedTest(name = "sha1Toggle={0}")
    @ValueSource(booleans = { true, false })
    void noX5tS256Member_whenSha256ToggleDefaultOff(boolean sha1ToggleEnabled) throws Exception {
        String pem = fixtureText(PEM_WITH_CERT);
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "INLINE",
                "content",
                pem,
                "x509CertSha1Thumbprint",
                sha1ToggleEnabled,
                "x509CertSha256Thumbprint",
                false
            )
        );

        Map<String, Object> header = decodeHeader(generateJwt(configuration));

        assertFalse(header.containsKey("x5t#S256"), "no x5t#S256 member must be emitted when the SHA-256 toggle is off");
        assertEquals(
            sha1ToggleEnabled,
            header.containsKey("x5t"),
            "x5t presence must follow the x5t (SHA-1) toggle independently of the SHA-256 toggle"
        );
        if (sha1ToggleEnabled) {
            assertEquals(PINNED_PEM_WITH_CERT_X5T, header.get("x5t"), "x5t must equal base64url(SHA-1(DER(leaf cert)))");
            assertEquals(Set.of("alg", "x5t"), header.keySet(), "the header member set must contain only alg and x5t");
        } else {
            assertEquals(
                Set.of("alg"),
                header.keySet(),
                "the header member set must be identical to the pre-feature baseline for this config"
            );
        }
    }

    @ParameterizedTest(name = "sha1Toggle={0}")
    @ValueSource(booleans = { true, false })
    void headerReflectsSha1Toggle_whileSha256AlwaysEmitted(boolean sha1ToggleEnabled) throws Exception {
        String pem = fixtureText(PEM_WITH_CERT);
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "INLINE",
                "content",
                pem,
                "x509CertSha1Thumbprint",
                sha1ToggleEnabled,
                "x509CertSha256Thumbprint",
                true
            )
        );

        Map<String, Object> header = decodeHeader(generateJwt(configuration));

        assertEquals(sha1ToggleEnabled, header.containsKey("x5t"), "x5t presence must follow the x5t (SHA-1) toggle");
        if (sha1ToggleEnabled) {
            assertEquals(PINNED_PEM_WITH_CERT_X5T, header.get("x5t"), "x5t must equal base64url(SHA-1(DER(leaf cert)))");
        }
        assertTrue(header.containsKey("x5t#S256"), "x5t#S256 toggle enabled must emit x5t#S256");
        assertEquals(PINNED_PEM_WITH_CERT_X5T_S256, header.get("x5t#S256"), "x5t#S256 must equal base64url(SHA-256(DER(leaf cert)))");
    }

    @Test
    void noX5tS256AndUnchangedHeaderKeySet_whenDeployedConfigJsonOmitsThumbprintField() throws Exception {
        String legacyConfigJson = String.format(
            "{\"signature\":\"RSA_RS256\",\"keyResolver\":\"JKS\",\"content\":\"%s\",\"alias\":\"%s\",\"storepass\":\"%s\",\"keypass\":\"%s\",\"kid\":\"legacy-kid\"}",
            uniqueCopy(GRAVITEEIO_JKS, ".jks"),
            GRAVITEEIO_JKS_ALIAS,
            GRAVITEEIO_JKS_STOREPASS,
            GRAVITEEIO_JKS_KEYPASS
        );

        GenerateJwtPolicyConfiguration legacyConfiguration = new ObjectMapper()
            .readValue(legacyConfigJson, GenerateJwtPolicyConfiguration.class);

        assertFalse(
            legacyConfiguration.isX509CertSha256Thumbprint(),
            "a deployed config JSON omitting the x509CertSha256Thumbprint field must parse with the field defaulted to false"
        );

        Map<String, Object> header = decodeHeader(generateJwt(legacyConfiguration));

        assertEquals(
            Set.of("alg", "kid"),
            header.keySet(),
            "a policy driven by a parsed legacy config must keep the exact pre-feature header member set: no x5t#S256 and no other new member"
        );
    }

    static Stream<Arguments> resolverFixtures() {
        return Stream.of(
            Arguments.of("INLINE", (ResolverSetup) GenerateJwtPolicyX5tS256ThumbprintTest::inlineFixture),
            Arguments.of("PEM", (ResolverSetup) GenerateJwtPolicyX5tS256ThumbprintTest::pemFixture),
            Arguments.of("JKS", (ResolverSetup) GenerateJwtPolicyX5tS256ThumbprintTest::jksFixture),
            Arguments.of("PKCS12", (ResolverSetup) GenerateJwtPolicyX5tS256ThumbprintTest::pkcs12Fixture)
        );
    }

    private Fixture inlineFixture() throws Exception {
        String pem = fixtureText(PEM_WITH_CERT);
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of("signature", "RSA_RS256", "keyResolver", "INLINE", "content", pem, "x509CertSha256Thumbprint", true)
        );
        return new Fixture(configuration, PINNED_PEM_WITH_CERT_X5T_S256);
    }

    private Fixture pemFixture() throws Exception {
        String pemPath = uniqueCopy(PEM_WITH_CERT, ".pem");
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of("signature", "RSA_RS256", "keyResolver", "PEM", "content", pemPath, "x509CertSha256Thumbprint", true)
        );
        return new Fixture(configuration, PINNED_PEM_WITH_CERT_X5T_S256);
    }

    private Fixture jksFixture() throws Exception {
        String keystorePath = uniqueCopy(GRAVITEEIO_JKS, ".jks");
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "JKS",
                "content",
                keystorePath,
                "alias",
                GRAVITEEIO_JKS_ALIAS,
                "storepass",
                GRAVITEEIO_JKS_STOREPASS,
                "keypass",
                GRAVITEEIO_JKS_KEYPASS,
                "x509CertSha256Thumbprint",
                true
            )
        );
        return new Fixture(configuration, PINNED_GRAVITEEIO_JKS_X5T_S256);
    }

    private Fixture pkcs12Fixture() throws Exception {
        String keystorePath = uniqueCopy(GRAVITEEIO_P12, ".p12");
        GenerateJwtPolicyConfiguration configuration = config(
            Map.of(
                "signature",
                "RSA_RS256",
                "keyResolver",
                "PKCS12",
                "content",
                keystorePath,
                "alias",
                GRAVITEEIO_P12_ALIAS,
                "storepass",
                GRAVITEEIO_P12_STOREPASS,
                "x509CertSha256Thumbprint",
                true
            )
        );
        return new Fixture(configuration, PINNED_GRAVITEEIO_P12_X5T_S256);
    }

    private GenerateJwtPolicyConfiguration config(Map<String, Object> properties) {
        return new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .convertValue(properties, GenerateJwtPolicyConfiguration.class);
    }

    private String generateJwt(GenerateJwtPolicyConfiguration configuration) {
        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        return (String) captor.getValue();
    }

    private Map<String, Object> decodeHeader(String jwt) throws Exception {
        String protectedHeader = new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
        return JSONObjectUtils.parse(protectedHeader);
    }

    private String uniqueCopy(String resource, String suffix) throws Exception {
        Path source = new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath();
        Path target = Files.createTempFile("x5ts256-", suffix);
        target.toFile().deleteOnExit();
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        return target.toAbsolutePath().toString();
    }

    private String fixtureText(String resource) throws Exception {
        return Files.readString(new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath());
    }

    private Certificate[] loadKeystoreChain(String keystorePath, String storepass, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(Path.of(keystorePath))) {
            keyStore.load(in, storepass.toCharArray());
        }
        return keyStore.getCertificateChain(alias);
    }

    @FunctionalInterface
    private interface ResolverSetup {
        Fixture apply(GenerateJwtPolicyX5tS256ThumbprintTest test) throws Exception;
    }

    private static final class Fixture {

        private final GenerateJwtPolicyConfiguration configuration;
        private final String expectedX5tS256;

        private Fixture(GenerateJwtPolicyConfiguration configuration, String expectedX5tS256) {
            this.configuration = configuration;
            this.expectedX5tS256 = expectedX5tS256;
        }

        private GenerateJwtPolicyConfiguration configuration() {
            return configuration;
        }

        private String expectedX5tS256() {
            return expectedX5tS256;
        }
    }
}
