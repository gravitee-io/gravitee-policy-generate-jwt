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
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import io.gravitee.reporter.api.http.Metrics;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.ThrowingConsumer;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Regression tests for the x5t (SHA-1 certificate thumbprint) JWS header parameter.
 *
 * @author GraviteeSource Team
 */
class GenerateJwtPolicyX5tThumbprintTest {

    private static final String GRAVITEEIO_JKS = "/graviteeio.jks";
    private static final String GRAVITEEIO_JKS_STOREPASS = "graviteeio.my.storepass";
    private static final String GRAVITEEIO_JKS_KEYPASS = "graviteeio.my.keypass";
    private static final String GRAVITEEIO_JKS_ALIAS = "graviteeio";

    private static final String CHAIN_JKS = "/graviteeio-chain.jks";
    private static final String CHAIN_JKS_STOREPASS = "chain.my.storepass";
    private static final String CHAIN_JKS_KEYPASS = "chain.my.keypass";
    private static final String CHAIN_JKS_ALIAS = "leaf";

    private static final String PINNED_GRAVITEEIO_JKS_X5T = "QSfzKW4MCLGqZye46EVLJF7n8dc";

    private static final String GRAVITEEIO_P12 = "/graviteeio.p12";
    private static final String GRAVITEEIO_P12_STOREPASS = "graviteeio.my.storepass";
    private static final String GRAVITEEIO_P12_ALIAS = "graviteeio";
    private static final String PINNED_GRAVITEEIO_P12_X5T = "4mI24XZ5gby7ccxpRauwjw88pTQ";

    private static final String PEM_WITH_CERT = "/priv-with-cert.pem";
    private static final String PINNED_PEM_WITH_CERT_X5T = "1VIruVLp9rHaINhtafJpVjintZw";

    private static final String PEM_WITH_CA_FIRST_CHAIN = "/priv-with-chain-ca-first.pem";

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
    }

    @Test
    void jwsProtectedHeaderContainsNonEmptyX5t_whenToggleEnabled() throws Exception {
        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);

        Map<String, Object> header = decodeHeader(generateJwt());

        assertTrue(header.containsKey("x5t"), "protected header must contain an x5t member");
        assertTrue(header.get("x5t") instanceof String, "x5t must be a string");
        assertFalse(((String) header.get("x5t")).isEmpty(), "x5t must be non-empty");
    }

    @Test
    void noX5tHeader_whenToggleDisabled() throws Exception {
        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);

        Map<String, Object> header = decodeHeader(generateJwt());

        assertFalse(header.containsKey("x5t"), "x5t must not be present when the toggle is disabled");
    }

    @Test
    void headerContainsExactPreFeatureMembers_whenThumbprintDisabledWithX5cAndKidConfigured() throws Exception {
        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKid()).thenReturn("test-kid-1");

        Map<String, Object> header = decodeHeader(generateJwt());

        assertEquals(
            Set.of("alg", "kid", "x5c"),
            header.keySet(),
            "with the thumbprint toggle off, a kid+X5C JKS config must keep the exact pre-feature header member set: no x5t and no other new member"
        );
    }

    @Test
    void headerContainsExactExpectedMembers_whenOnlyX5tToggleEnabled() throws Exception {
        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);
        when(configuration.getKid()).thenReturn("test-kid-1");

        Map<String, Object> header = decodeHeader(generateJwt());

        assertEquals(
            Set.of("alg", "kid", "x5t"),
            header.keySet(),
            "header must contain exactly alg, kid, and x5t, with no unexpected or leaked members such as x5c"
        );
        assertEquals("RS256", header.get("alg"));
        assertEquals("test-kid-1", header.get("kid"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cacheHitResolverStubs")
    void x5tRemainsCorrect_onSignerCacheHit(
        String resolverName,
        ThrowingConsumer<GenerateJwtPolicyX5tThumbprintTest> resolverStub,
        String pinnedX5t
    ) throws Throwable {
        resolverStub.accept(this);
        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);
        policy.onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(2)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());

        for (Object jwt : captor.getAllValues()) {
            String x5t = (String) decodeHeader((String) jwt).get("x5t");
            assertEquals(pinnedX5t, x5t, "x5t must remain correct whether the signer came from a cache miss or a cache hit");
        }
    }

    static Stream<Arguments> cacheHitResolverStubs() {
        return Stream.of(
            Arguments.of(
                "JKS",
                (ThrowingConsumer<GenerateJwtPolicyX5tThumbprintTest>) test ->
                    test.stubJksResolver(
                        test.uniqueCopy(GRAVITEEIO_JKS),
                        GRAVITEEIO_JKS_ALIAS,
                        GRAVITEEIO_JKS_STOREPASS,
                        GRAVITEEIO_JKS_KEYPASS
                    ),
                PINNED_GRAVITEEIO_JKS_X5T
            ),
            Arguments.of(
                "PEM",
                (ThrowingConsumer<GenerateJwtPolicyX5tThumbprintTest>) test -> test.stubPemResolver(test.uniqueCopy(PEM_WITH_CERT, ".pem")),
                PINNED_PEM_WITH_CERT_X5T
            )
        );
    }

    @Test
    void x5tDoesNotLeakBetweenDifferentCachedCertificates() throws Exception {
        stubJksResolver(uniqueCopy(CHAIN_JKS), CHAIN_JKS_ALIAS, CHAIN_JKS_STOREPASS, CHAIN_JKS_KEYPASS);
        String otherApiX5t = (String) decodeHeader(generateJwt()).get("x5t");

        clearInvocations(policyChain, executionContext);

        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);
        String thisApiX5t = (String) decodeHeader(generateJwt()).get("x5t");

        assertEquals(
            PINNED_GRAVITEEIO_JKS_X5T,
            thisApiX5t,
            "this API's x5t must be its own leaf thumbprint, not leaked from a different API's cached chain"
        );
        assertNotEquals(otherApiX5t, thisApiX5t, "two APIs backed by different certificates must never share an x5t value");
    }

    @Test
    void x5tIsBase64UrlOfSha1OfLeafDer_pinnedAgainstGraviteeioJks() throws Exception {
        String keystorePath = uniqueCopy(GRAVITEEIO_JKS);
        stubJksResolver(keystorePath, GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);

        Base64URL x5t = generateSignedJwt().getHeader().getX509CertThumbprint();

        assertEquals(PINNED_GRAVITEEIO_JKS_X5T, x5t.toString());

        byte[] decoded = x5t.decode();
        assertEquals(20, decoded.length, "SHA-1 digest must be 20 bytes");

        X509Certificate leaf = loadLeaf(keystorePath, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_ALIAS);
        byte[] expected = MessageDigest.getInstance("SHA-1").digest(leaf.getEncoded());
        assertArrayEquals(expected, decoded, "x5t must decode to SHA-1(DER(leaf cert)), not a hash of other material");
    }

    @Test
    void x5tComputedFromLeafOnly_whenChainHasMultipleEntries() throws Exception {
        String keystorePath = uniqueCopy(CHAIN_JKS);
        stubJksResolver(keystorePath, CHAIN_JKS_ALIAS, CHAIN_JKS_STOREPASS, CHAIN_JKS_KEYPASS);

        String x5t = generateSignedJwt().getHeader().getX509CertThumbprint().toString();

        Certificate[] chain = loadChain(keystorePath, CHAIN_JKS_STOREPASS, CHAIN_JKS_ALIAS);
        assertTrue(chain.length >= 2, "fixture must supply a multi-entry chain (leaf + CA)");

        String leafX5t = sha1Base64Url(chain[0]);
        String caX5t = sha1Base64Url(chain[chain.length - 1]);

        assertEquals(leafX5t, x5t, "x5t must equal the leaf (chain[0]) thumbprint");
        assertNotEquals(caX5t, x5t, "x5t must NOT equal a non-leaf entry's thumbprint");
    }

    @Test
    void x5tIsLeafCertThumbprint_whenPkcs12ResolverSuppliesSigningCertificate() throws Exception {
        stubPkcs12Resolver(uniqueCopy(GRAVITEEIO_P12, ".p12"), GRAVITEEIO_P12_ALIAS, GRAVITEEIO_P12_STOREPASS);

        Base64URL x5t = generateSignedJwt().getHeader().getX509CertThumbprint();

        assertNotNull(x5t, "PKCS12 resolver must emit x5t when the keystore carries a certificate and the toggle is enabled");
        assertEquals(PINNED_GRAVITEEIO_P12_X5T, x5t.toString());
    }

    @Test
    void x5tIsLeafCertThumbprint_whenPemResolverContentCarriesCertificate() throws Exception {
        String pemPath = uniqueCopy(PEM_WITH_CERT, ".pem");
        stubPemResolver(pemPath);

        Base64URL x5t = generateSignedJwt().getHeader().getX509CertThumbprint();

        assertNotNull(x5t, "PEM resolver must emit x5t when its content carries a CERTIFICATE block and the toggle is enabled");
        assertEquals(PINNED_PEM_WITH_CERT_X5T, x5t.toString());
        assertEquals(
            sha1Base64Url(loadPemCertificate(pemPath)),
            x5t.toString(),
            "x5t must equal SHA-1(DER(certificate embedded in the PEM content))"
        );
    }

    @Test
    void x5tIsLeafCertThumbprint_whenInlineResolverContentCarriesCertificate() throws Exception {
        stubInlineResolver(fixtureText(PEM_WITH_CERT));

        Base64URL x5t = generateSignedJwt().getHeader().getX509CertThumbprint();

        assertNotNull(x5t, "INLINE resolver must emit x5t when its content carries a CERTIFICATE block and the toggle is enabled");
        assertEquals(PINNED_PEM_WITH_CERT_X5T, x5t.toString());
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void x5cHeaderCarriesEmbeddedCertificate_whenX5cConfiguredWithThumbprintEnabled(KeyResolver keyResolver) throws Exception {
        stubCertBearingResolver(keyResolver);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);

        Map<String, Object> header = decodeHeader(generateJwt());

        assertEquals(
            Set.of("alg", "x5t", "x5c"),
            header.keySet(),
            keyResolver + " resolver with X5C configured and the x5t toggle on must emit both x5c and x5t"
        );
        assertEquals(
            fixtureCertificateBase64(),
            ((List<?>) header.get("x5c")).get(0).toString(),
            "x5c[0] must be the standard-Base64 DER of the certificate embedded in the key content"
        );
        assertEquals(PINNED_PEM_WITH_CERT_X5T, header.get("x5t"), "x5t must still follow its own toggle when X5C is configured");
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void x5cHeaderWithoutX5t_whenX5cConfiguredWithThumbprintDisabled(KeyResolver keyResolver) throws Exception {
        stubCertBearingResolver(keyResolver);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);

        Map<String, Object> header = decodeHeader(generateJwt());

        assertEquals(
            Set.of("alg", "x5c"),
            header.keySet(),
            keyResolver + " resolver with X5C configured and the x5t toggle off must emit x5c from the embedded certificate but no x5t"
        );
        assertEquals(
            fixtureCertificateBase64(),
            ((List<?>) header.get("x5c")).get(0).toString(),
            "x5c[0] must be the standard-Base64 DER of the certificate embedded in the key content"
        );
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void x5tBackfilled_whenToggleEnabledAfterSignerCachedWithToggleOff(KeyResolver keyResolver) throws Exception {
        stubCertBearingResolver(keyResolver);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        assertFalse(decodeHeader(generateJwt()).containsKey("x5t"), "pre-condition: the toggle-off warm-up request must not emit x5t");

        clearInvocations(policyChain, executionContext);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);

        Map<String, Object> header = decodeHeader(generateJwt());

        assertEquals(
            PINNED_PEM_WITH_CERT_X5T,
            header.get("x5t"),
            keyResolver +
            " resolver must backfill the leaf certificate and emit x5t on a signer cache hit when the toggle turns on after a toggle-off load"
        );
    }

    @Test
    void x5cLeadsWithSigningCertificateAndX5tMatchesIt_whenInlineContentBundlesCaFirstChain() throws Exception {
        String pem = fixtureText(PEM_WITH_CA_FIRST_CHAIN);
        stubInlineResolver(pem);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);

        Map<String, Object> header = decodeHeader(generateJwt());

        X509Certificate signingCertificate = signingCertificateOf(pem);
        List<?> x5c = (List<?>) header.get("x5c");
        assertEquals(
            Base64.getEncoder().encodeToString(signingCertificate.getEncoded()),
            x5c.get(0).toString(),
            "x5c[0] must be the signing certificate's DER even when the CA certificate appears first in the PEM content"
        );
        assertEquals(
            sha1Base64Url(signingCertificate),
            header.get("x5t"),
            "x5t must be the SHA-1 thumbprint of x5c[0], the signing certificate"
        );
    }

    @Test
    void x5tIsExactly27Base64UrlCharsWithNoPadding() throws Exception {
        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);

        String x5t = generateSignedJwt().getHeader().getX509CertThumbprint().toString();

        assertEquals(27, x5t.length(), "20-byte SHA-1 digest encodes to 27 base64url chars");
        assertTrue(x5t.matches("^[A-Za-z0-9_-]{27}$"), "x5t must match the base64url alphabet");
        assertFalse(x5t.contains("="), "x5t must have no '=' padding");
        assertFalse(x5t.contains("+"), "x5t must not contain '+'");
        assertFalse(x5t.contains("/"), "x5t must not contain '/'");
    }

    @Test
    void x5tEmittedAndRequestProceeds_whenSignatureIsNullWithThumbprintEnabled() throws Exception {
        stubPemResolver(uniqueCopy(PEM_WITH_CERT, ".pem"));
        when(configuration.getSignature()).thenReturn(null);

        Map<String, Object> header = decodeHeader(generateJwt());

        verify(policyChain, never()).failWith(any());
        assertEquals("RS256", header.get("alg"), "a null signature must follow the default RSA path");
        assertEquals(
            PINNED_PEM_WITH_CERT_X5T,
            header.get("x5t"),
            "a null signature with the thumbprint toggle enabled must default to the RSA path and emit x5t"
        );
    }

    @Test
    void noX5tOnCacheHit_whenThumbprintDisabledButLeafCertificateAlreadyCached() throws Exception {
        stubJksResolver(uniqueCopy(GRAVITEEIO_JKS), GRAVITEEIO_JKS_ALIAS, GRAVITEEIO_JKS_STOREPASS, GRAVITEEIO_JKS_KEYPASS);
        assertTrue(
            decodeHeader(generateJwt()).containsKey("x5t"),
            "pre-condition: the toggle-on warm-up request must emit x5t and cache the leaf certificate"
        );

        clearInvocations(policyChain, executionContext);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);

        Map<String, Object> header = decodeHeader(generateJwt());

        assertEquals(
            Set.of("alg"),
            header.keySet(),
            "a toggle-off config must keep the exact pre-feature header on a cache hit, even when a toggle-on config sharing the same key material already cached the leaf certificate"
        );
    }

    @Test
    void noX5tAndUnchangedHeaderKeySet_whenDeployedConfigJsonOmitsThumbprintField() throws Exception {
        String legacyConfigJson = String.format(
            "{\"signature\":\"RSA_RS256\",\"keyResolver\":\"JKS\",\"content\":\"%s\",\"alias\":\"%s\",\"storepass\":\"%s\",\"keypass\":\"%s\",\"kid\":\"legacy-kid\"}",
            uniqueCopy(GRAVITEEIO_JKS),
            GRAVITEEIO_JKS_ALIAS,
            GRAVITEEIO_JKS_STOREPASS,
            GRAVITEEIO_JKS_KEYPASS
        );

        GenerateJwtPolicyConfiguration legacyConfiguration = new ObjectMapper()
            .readValue(legacyConfigJson, GenerateJwtPolicyConfiguration.class);

        assertFalse(
            legacyConfiguration.isX509CertSha1Thumbprint(),
            "a deployed config JSON omitting the thumbprint field must parse with the field defaulted to false"
        );

        Map<String, Object> header = decodeHeader(generateJwt(legacyConfiguration));

        assertEquals(
            Set.of("alg", "kid"),
            header.keySet(),
            "a policy driven by a parsed legacy config must keep the exact pre-feature header member set: no x5t and no other new member"
        );
    }

    private void stubCertBearingResolver(KeyResolver keyResolver) throws Exception {
        if (keyResolver == KeyResolver.PEM) {
            stubPemResolver(uniqueCopy(PEM_WITH_CERT, ".pem"));
        } else {
            stubInlineResolver(uniqueInlineContent());
        }
    }

    private String uniqueInlineContent() throws Exception {
        return fixtureText(PEM_WITH_CERT) + "\n" + UUID.randomUUID() + "\n";
    }

    private void stubInlineResolver(String content) {
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.INLINE);
        when(configuration.getContent()).thenReturn(content);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
    }

    private void stubPemResolver(String content) {
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.PEM);
        when(configuration.getContent()).thenReturn(content);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
    }

    private void stubPkcs12Resolver(String content, String alias, String storepass) {
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.PKCS12);
        when(configuration.getAlias()).thenReturn(alias);
        when(configuration.getStorepass()).thenReturn(storepass);
        when(configuration.getContent()).thenReturn(content);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
    }

    private void stubJksResolver(String content, String alias, String storepass, String keypass) {
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.JKS);
        when(configuration.getAlias()).thenReturn(alias);
        when(configuration.getStorepass()).thenReturn(storepass);
        when(configuration.getKeypass()).thenReturn(keypass);
        when(configuration.getContent()).thenReturn(content);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
    }

    private String generateJwt() {
        return generateJwt(configuration);
    }

    private String generateJwt(GenerateJwtPolicyConfiguration policyConfiguration) {
        new GenerateJwtPolicy(policyConfiguration).onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        return (String) captor.getValue();
    }

    private SignedJWT generateSignedJwt() throws Exception {
        return SignedJWT.parse(generateJwt());
    }

    private Map<String, Object> decodeHeader(String jwt) throws Exception {
        String protectedHeader = new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
        return JSONObjectUtils.parse(protectedHeader);
    }

    private String uniqueCopy(String resource) throws Exception {
        return uniqueCopy(resource, ".jks");
    }

    private String uniqueCopy(String resource, String suffix) throws Exception {
        Path source = new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath();
        Path target = Files.createTempFile("x5t-", suffix);
        target.toFile().deleteOnExit();
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        return target.toAbsolutePath().toString();
    }

    private String fixtureText(String resource) throws Exception {
        return Files.readString(new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath());
    }

    private X509Certificate loadPemCertificate(String pemPath) throws Exception {
        return parsePemCertificate(Files.readString(Path.of(pemPath)));
    }

    private X509Certificate parsePemCertificate(String pem) throws Exception {
        String certPem = pem.substring(pem.indexOf("-----BEGIN CERTIFICATE-----"));
        return (X509Certificate) CertificateFactory
            .getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
    }

    private X509Certificate signingCertificateOf(String pem) throws Exception {
        String certificatesPem = pem.substring(pem.indexOf("-----BEGIN CERTIFICATE-----"), pem.indexOf("-----BEGIN PRIVATE KEY-----"));
        List<X509Certificate> signingCertificates = CertificateFactory
            .getInstance("X.509")
            .generateCertificates(new ByteArrayInputStream(certificatesPem.getBytes(StandardCharsets.UTF_8)))
            .stream()
            .map(X509Certificate.class::cast)
            .filter(certificate -> !certificate.getSubjectX500Principal().equals(certificate.getIssuerX500Principal()))
            .toList();
        assertEquals(1, signingCertificates.size(), "fixture must carry exactly one non-self-signed (signing) certificate");
        return signingCertificates.get(0);
    }

    private String fixtureCertificateBase64() throws Exception {
        return Base64.getEncoder().encodeToString(parsePemCertificate(fixtureText(PEM_WITH_CERT)).getEncoded());
    }

    private X509Certificate loadLeaf(String keystorePath, String storepass, String alias) throws Exception {
        return (X509Certificate) loadChain(keystorePath, storepass, alias)[0];
    }

    private Certificate[] loadChain(String keystorePath, String storepass, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream in = Files.newInputStream(Path.of(keystorePath))) {
            keyStore.load(in, storepass.toCharArray());
        }
        return keyStore.getCertificateChain(alias);
    }

    private String sha1Base64Url(Certificate certificate) throws Exception {
        return Base64URL.encode(MessageDigest.getInstance("SHA-1").digest(certificate.getEncoded())).toString();
    }
}
