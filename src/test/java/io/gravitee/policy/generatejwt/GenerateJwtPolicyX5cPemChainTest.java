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
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.reporter.api.http.Metrics;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class GenerateJwtPolicyX5cPemChainTest {

    private static final String PEM_WITH_CERT = "/priv-with-cert.pem";
    private static final String PEM_NO_CERT = "/priv.pem";

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
    void x5cHeaderCarriesPemCertificate_whenPemResolverConfiguresX5cWithThumbprintDisabled() throws Exception {
        String pemPath = uniqueCopy(PEM_WITH_CERT);
        String deployedConfigJson = String.format(
            "{\"signature\":\"RSA_RS256\",\"keyResolver\":\"PEM\",\"content\":\"%s\",\"x509CertificateChain\":\"X5C\",\"x509CertSha1Thumbprint\":false}",
            pemPath
        );

        GenerateJwtPolicyConfiguration configuration = new ObjectMapper()
            .readValue(deployedConfigJson, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        Map<String, Object> header = decodeHeader((String) captor.getValue());

        assertTrue(
            header.containsKey("x5c"),
            "PEM resolver with X5C configured must emit an x5c header from the certificate embedded in the PEM content"
        );
        List<?> x5c = (List<?>) header.get("x5c");
        assertFalse(x5c.isEmpty(), "x5c must be a non-empty chain");
        assertEquals(
            Base64.getEncoder().encodeToString(loadPemCertificate(pemPath).getEncoded()),
            x5c.get(0).toString(),
            "x5c[0] must be the standard-Base64 DER of the certificate embedded in the PEM content"
        );
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void silentNoOp_whenContentHasNoCertificateAndX5cIsOff(KeyResolver keyResolver) throws Exception {
        String content = keyResolver == KeyResolver.PEM ? uniqueCopy(PEM_NO_CERT) : fixtureText(PEM_NO_CERT);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", keyResolver.name());
        config.put("content", content);
        config.put("x509CertificateChain", "NONE");
        config.put("x509CertSha1Thumbprint", false);

        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        assertSilentNoOp(configuration);
    }

    @Test
    void rejectsRequest_whenX5cRequestedButPemCertificateDoesNotMatchSigningKey() throws Exception {
        String mismatchedPem = fixtureText(PEM_NO_CERT) + "\n" + certificateBlock(PEM_WITH_CERT);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", mismatchedPem);
        config.put("x509CertificateChain", "X5C");
        config.put("x509CertSha1Thumbprint", false);

        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(1)).failWith(captor.capture());
        assertEquals(
            500,
            captor.getValue().statusCode(),
            "x5c requested with a certificate not matching the signing key must fail with HTTP 500"
        );
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    @Test
    void rejectsX5cRequest_whenSharedCacheWasPrimedByEarlierX5tOnlyRequestWithUnmatchedCertificate() throws Exception {
        String mismatchedPem = fixtureText(PEM_NO_CERT) + "\n" + certificateBlock(PEM_WITH_CERT);

        ObjectMapper mapper = new ObjectMapper();

        ObjectNode thumbprintOnlyConfig = mapper.createObjectNode();
        thumbprintOnlyConfig.put("signature", "RSA_RS256");
        thumbprintOnlyConfig.put("keyResolver", "INLINE");
        thumbprintOnlyConfig.put("content", mismatchedPem);
        thumbprintOnlyConfig.put("x509CertificateChain", "NONE");
        thumbprintOnlyConfig.put("x509CertSha1Thumbprint", true);
        GenerateJwtPolicyConfiguration thumbprintOnly = mapper.treeToValue(thumbprintOnlyConfig, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(thumbprintOnly).onRequest(request, response, executionContext, policyChain);

        ObjectNode x5cConfig = mapper.createObjectNode();
        x5cConfig.put("signature", "RSA_RS256");
        x5cConfig.put("keyResolver", "INLINE");
        x5cConfig.put("content", mismatchedPem);
        x5cConfig.put("x509CertificateChain", "X5C");
        x5cConfig.put("x509CertSha1Thumbprint", false);
        GenerateJwtPolicyConfiguration x5c = mapper.treeToValue(x5cConfig, GenerateJwtPolicyConfiguration.class);

        PolicyChain x5cPolicyChain = mock(PolicyChain.class);
        ExecutionContext x5cExecutionContext = mock(ExecutionContext.class);
        when(x5cExecutionContext.getTemplateEngine()).thenReturn(templateEngine);

        new GenerateJwtPolicy(x5c).onRequest(request, response, x5cExecutionContext, x5cPolicyChain);

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(x5cPolicyChain, times(1)).failWith(captor.capture());
        assertEquals(
            500,
            captor.getValue().statusCode(),
            "x5c requested against a cache primed by an unmatched-certificate thumbprint request must fail with HTTP 500"
        );
        verify(x5cPolicyChain, never()).doNext(any(), any());
        verify(x5cExecutionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void rejectsRequestWith500_whenX5cRequestedAndContentHasNoCertificateBlock(KeyResolver keyResolver) throws Exception {
        String content = keyResolver == KeyResolver.PEM ? uniqueCopy(PEM_NO_CERT) : fixtureText(PEM_NO_CERT);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", keyResolver.name());
        config.put("content", content);
        config.put("x509CertificateChain", "X5C");
        config.put("x509CertSha1Thumbprint", false);

        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(1)).failWith(captor.capture());
        assertEquals(500, captor.getValue().statusCode(), "x5c requested with no certificate block must fail with HTTP 500");
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    private static Stream<Arguments> x5cContentCases() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Date notBefore = Date.from(Instant.now().minusSeconds(3_600));
        Date notAfter = Date.from(Instant.now().plusSeconds(3_600 * 24 * 365));

        X500Name rootSubject = new X500Name("CN=Test Root CA");
        X500Name intermediateSubject = new X500Name("CN=Test Intermediate CA");
        X500Name leafSubject = new X500Name("CN=Test Leaf");
        X500Name unrelatedSubject = new X500Name("CN=Unrelated CA");

        // Full chain, bundle order is deliberately root-first ([root, intermediate, leaf]) — the
        // signing cert (leaf) is NOT first in the file, so a correct implementation must reorder by
        // issuer/subject linkage rather than trusting file order for the non-signing certificates.
        CertificateWithKey root = issueCertificate(rootSubject, null, null, true, notBefore, notAfter);
        CertificateWithKey intermediate = issueCertificate(
            intermediateSubject,
            rootSubject,
            root.keyPair().getPrivate(),
            true,
            notBefore,
            notAfter
        );
        CertificateWithKey leaf = issueCertificate(
            leafSubject,
            intermediateSubject,
            intermediate.keyPair().getPrivate(),
            false,
            notBefore,
            notAfter
        );
        X509Certificate rootCert = root.certificate();
        X509Certificate intermediateCert = intermediate.certificate();
        X509Certificate leafCert = leaf.certificate();
        String fullChainPem =
            pemEncodePrivateKey(leaf.keyPair().getPrivate()) +
            "\n" +
            pemEncodeCertificate(rootCert) +
            "\n" +
            pemEncodeCertificate(intermediateCert) +
            "\n" +
            pemEncodeCertificate(leafCert);
        List<String> fullChainExpected = List.of(
            Base64.getEncoder().encodeToString(leafCert.getEncoded()),
            Base64.getEncoder().encodeToString(intermediateCert.getEncoded()),
            Base64.getEncoder().encodeToString(rootCert.getEncoded())
        );

        // No bundle certificate links to the leaf — the leaf's issuer has no matching certificate
        // in the bundle, so the chain must contain only the leaf itself.
        CertificateWithKey unrelatedForNoLink = issueCertificate(unrelatedSubject, null, null, true, notBefore, notAfter);
        X500Name absentIntermediateSubject = new X500Name("CN=Absent Intermediate CA");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair absentIntermediateKeyPair = keyPairGenerator.generateKeyPair();
        CertificateWithKey noLinkLeaf = issueCertificate(
            leafSubject,
            absentIntermediateSubject,
            absentIntermediateKeyPair.getPrivate(),
            false,
            notBefore,
            notAfter
        );
        X509Certificate noLinkLeafCert = noLinkLeaf.certificate();
        String noLinkPem =
            pemEncodePrivateKey(noLinkLeaf.keyPair().getPrivate()) +
            "\n" +
            pemEncodeCertificate(noLinkLeafCert) +
            "\n" +
            pemEncodeCertificate(unrelatedForNoLink.certificate());
        List<String> noLinkExpected = List.of(Base64.getEncoder().encodeToString(noLinkLeafCert.getEncoded()));

        // Bundle has a linked intermediate plus an unrelated CA — the unrelated certificate must be
        // dropped while the linked intermediate is kept.
        CertificateWithKey partialIntermediate = issueCertificate(intermediateSubject, null, null, true, notBefore, notAfter);
        CertificateWithKey partialLeaf = issueCertificate(
            leafSubject,
            intermediateSubject,
            partialIntermediate.keyPair().getPrivate(),
            false,
            notBefore,
            notAfter
        );
        CertificateWithKey partialUnrelated = issueCertificate(unrelatedSubject, null, null, true, notBefore, notAfter);
        X509Certificate partialIntermediateCert = partialIntermediate.certificate();
        X509Certificate partialLeafCert = partialLeaf.certificate();
        String partialDropPem =
            pemEncodePrivateKey(partialLeaf.keyPair().getPrivate()) +
            "\n" +
            pemEncodeCertificate(partialLeafCert) +
            "\n" +
            pemEncodeCertificate(partialIntermediateCert) +
            "\n" +
            pemEncodeCertificate(partialUnrelated.certificate());
        List<String> partialDropExpected = List.of(
            Base64.getEncoder().encodeToString(partialLeafCert.getEncoded()),
            Base64.getEncoder().encodeToString(partialIntermediateCert.getEncoded())
        );

        return Stream.of(
            Arguments.of("x5cChainIsOrderedLeafToRoot_whenPemBundleIsRootFirstWithThreeCertificates", fullChainPem, fullChainExpected),
            Arguments.of("x5cContainsOnlySigningCertificate_whenNoBundleCertificateLinksToIt", noLinkPem, noLinkExpected),
            Arguments.of("x5cDropsUnlinkableCertificate_whenBundleHasLinkedIntermediateAndUnrelatedCa", partialDropPem, partialDropExpected)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("x5cContentCases")
    void x5cContainsExactlyTheLinkedChainInLeafToRootOrder(String caseName, String pemContent, List<String> expectedX5c) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", pemContent);
        config.put("x509CertificateChain", "X5C");
        config.put("x509CertSha1Thumbprint", false);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        Map<String, Object> header = decodeHeader((String) captor.getValue());
        List<?> x5c = (List<?>) header.get("x5c");

        assertEquals(
            expectedX5c,
            x5c.stream().map(Object::toString).collect(Collectors.toList()),
            "x5c must contain exactly the linked chain in leaf-first order, dropping any unlinkable certificate — case: " + caseName
        );
    }

    @Test
    void thumbprintsRemainSigningCertificateThumbprints_whenBundleTriggersCertificateDropping() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Date notBefore = Date.from(Instant.now().minusSeconds(3_600));
        Date notAfter = Date.from(Instant.now().plusSeconds(3_600 * 24 * 365));

        X500Name intermediateSubject = new X500Name("CN=Test Intermediate CA");
        X500Name leafSubject = new X500Name("CN=Test Leaf");
        X500Name unrelatedSubject = new X500Name("CN=Unrelated CA");

        CertificateWithKey intermediate = issueCertificate(intermediateSubject, null, null, true, notBefore, notAfter);
        CertificateWithKey leaf = issueCertificate(
            leafSubject,
            intermediateSubject,
            intermediate.keyPair().getPrivate(),
            false,
            notBefore,
            notAfter
        );
        CertificateWithKey unrelated = issueCertificate(unrelatedSubject, null, null, true, notBefore, notAfter);

        X509Certificate intermediateCert = intermediate.certificate();
        X509Certificate leafCert = leaf.certificate();
        X509Certificate unrelatedCaCert = unrelated.certificate();

        // Bundle order is deliberately leaf-last ([intermediate, unrelated, leaf]) so a thumbprint
        // wrongly derived from chain position 0 would differ from the signing (leaf) certificate's
        // actual digest, making the leaf-vs-chain-position contract able to fail if it regresses.
        String pemContent =
            pemEncodePrivateKey(leaf.keyPair().getPrivate()) +
            "\n" +
            pemEncodeCertificate(intermediateCert) +
            "\n" +
            pemEncodeCertificate(unrelatedCaCert) +
            "\n" +
            pemEncodeCertificate(leafCert);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", pemContent);
        config.put("x509CertificateChain", "X5C");
        config.put("x509CertSha1Thumbprint", true);
        config.put("x509CertSha256Thumbprint", true);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        Map<String, Object> header = decodeHeader((String) captor.getValue());

        List<?> x5c = (List<?>) header.get("x5c");
        assertEquals(
            2,
            x5c.size(),
            "pre-condition: the unrelated CA must be dropped so the bundle genuinely triggers certificate dropping"
        );

        assertEquals(
            Base64URL.encode(MessageDigest.getInstance("SHA-1").digest(leafCert.getEncoded())).toString(),
            header.get("x5t"),
            "x5t must be the SHA-1 thumbprint of the signing (leaf) certificate, never derived from the ordered/dropped chain"
        );
        assertEquals(
            Base64URL.encode(MessageDigest.getInstance("SHA-256").digest(leafCert.getEncoded())).toString(),
            header.get("x5t#S256"),
            "x5t#S256 must be the SHA-256 thumbprint of the signing (leaf) certificate, never derived from the ordered/dropped chain"
        );
    }

    @Test
    void x5cCertificateMatchesSigningKey_whenPemFileRotatedBetweenWarmUpAndX5cEnabled() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Date notBefore = Date.from(Instant.now().minusSeconds(3_600));
        Date notAfter = Date.from(Instant.now().plusSeconds(3_600 * 24 * 365));

        X500Name originalSubject = new X500Name("CN=Original");
        CertificateWithKey original = issueCertificate(originalSubject, null, null, false, notBefore, notAfter);
        KeyPair originalKeyPair = original.keyPair();
        X509Certificate originalCert = original.certificate();

        X500Name rotatedSubject = new X500Name("CN=Rotated");
        CertificateWithKey rotated = issueCertificate(rotatedSubject, null, null, false, notBefore, notAfter);
        KeyPair rotatedKeyPair = rotated.keyPair();
        X509Certificate rotatedCert = rotated.certificate();

        Path pemFile = Files.createTempFile("rotating-", ".pem");
        pemFile.toFile().deleteOnExit();
        Files.writeString(pemFile, pemEncodePrivateKey(originalKeyPair.getPrivate()) + "\n" + pemEncodeCertificate(originalCert));

        ObjectMapper mapper = new ObjectMapper();

        ObjectNode warmUpConfig = mapper.createObjectNode();
        warmUpConfig.put("signature", "RSA_RS256");
        warmUpConfig.put("keyResolver", "PEM");
        warmUpConfig.put("content", pemFile.toAbsolutePath().toString());
        warmUpConfig.put("x509CertificateChain", "NONE");
        warmUpConfig.put("x509CertSha1Thumbprint", false);
        GenerateJwtPolicyConfiguration warmUp = mapper.treeToValue(warmUpConfig, GenerateJwtPolicyConfiguration.class);
        new GenerateJwtPolicy(warmUp).onRequest(request, response, executionContext, policyChain);

        Files.writeString(pemFile, pemEncodePrivateKey(rotatedKeyPair.getPrivate()) + "\n" + pemEncodeCertificate(rotatedCert));

        clearInvocations(policyChain, executionContext);

        ObjectNode x5cConfig = mapper.createObjectNode();
        x5cConfig.put("signature", "RSA_RS256");
        x5cConfig.put("keyResolver", "PEM");
        x5cConfig.put("content", pemFile.toAbsolutePath().toString());
        x5cConfig.put("x509CertificateChain", "X5C");
        x5cConfig.put("x509CertSha1Thumbprint", false);
        GenerateJwtPolicyConfiguration x5c = mapper.treeToValue(x5cConfig, GenerateJwtPolicyConfiguration.class);
        new GenerateJwtPolicy(x5c).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());

        SignedJWT signedJWT = SignedJWT.parse((String) captor.getValue());
        List<com.nimbusds.jose.util.Base64> x5cChain = signedJWT.getHeader().getX509CertChain();
        X509Certificate advertisedCert = (X509Certificate) CertificateFactory
            .getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(x5cChain.get(0).decode()));

        assertTrue(
            signedJWT.verify(new RSASSAVerifier((RSAPublicKey) advertisedCert.getPublicKey())),
            "the JWT signature must verify against the public key of the certificate advertised in x5c — after an on-disk key rotation preceding x5c being enabled, the signing key and the advertised certificate must not diverge"
        );
    }

    private static final class CertificateWithKey {

        private final X509Certificate certificate;
        private final KeyPair keyPair;

        private CertificateWithKey(X509Certificate certificate, KeyPair keyPair) {
            this.certificate = certificate;
            this.keyPair = keyPair;
        }

        private X509Certificate certificate() {
            return certificate;
        }

        private KeyPair keyPair() {
            return keyPair;
        }
    }

    private static CertificateWithKey issueCertificate(
        X500Name subject,
        X500Name issuer,
        PrivateKey issuerKey,
        boolean isCa,
        Date notBefore,
        Date notAfter
    ) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        boolean selfSigned = issuer == null;
        X509Certificate certificate = buildCertificate(
            selfSigned ? subject : issuer,
            selfSigned ? keyPair.getPrivate() : issuerKey,
            subject,
            keyPair.getPublic(),
            notBefore,
            notAfter,
            isCa
        );
        return new CertificateWithKey(certificate, keyPair);
    }

    private static X509Certificate buildCertificate(
        X500Name issuer,
        PrivateKey issuerKey,
        X500Name subject,
        PublicKey subjectKey,
        Date notBefore,
        Date notAfter,
        boolean isCa
    ) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            notBefore,
            notAfter,
            subject,
            subjectKey
        );
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCa));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
    }

    private static String pemEncodeCertificate(X509Certificate certificate) throws Exception {
        return (
            "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(certificate.getEncoded()) +
            "\n-----END CERTIFICATE-----\n"
        );
    }

    private static String pemEncodePrivateKey(PrivateKey privateKey) {
        return (
            "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(privateKey.getEncoded()) +
            "\n-----END PRIVATE KEY-----\n"
        );
    }

    private String certificateBlock(String resource) throws Exception {
        String pem = fixtureText(resource);
        return pem.substring(pem.indexOf("-----BEGIN CERTIFICATE-----"));
    }

    private void assertSilentNoOp(GenerateJwtPolicyConfiguration configuration) throws Exception {
        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        Map<String, Object> header = decodeHeader((String) captor.getValue());

        assertEquals(
            Set.of("alg"),
            header.keySet(),
            "content with no CERTIFICATE block and X5C off must keep a minimal header: no x5c, no x5t"
        );
    }

    private String fixtureText(String resource) throws Exception {
        return Files.readString(new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath());
    }

    private Map<String, Object> decodeHeader(String jwt) throws Exception {
        String protectedHeader = new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
        return JSONObjectUtils.parse(protectedHeader);
    }

    private String uniqueCopy(String resource) throws Exception {
        Path source = new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath();
        Path target = Files.createTempFile("x5c-pem-", ".pem");
        target.toFile().deleteOnExit();
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        return target.toAbsolutePath().toString();
    }

    private X509Certificate loadPemCertificate(String pemPath) throws Exception {
        String pem = Files.readString(Path.of(pemPath));
        String certPem = pem.substring(pem.indexOf("-----BEGIN CERTIFICATE-----"));
        return (X509Certificate) CertificateFactory
            .getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
    }
}
