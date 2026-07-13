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
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.reporter.api.http.Metrics;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class GenerateJwtPolicyLegacyCertificateLabelTest {

    private static final String REAL_TRUSTED_CERT_PEM = "/priv-with-real-trusted-cert.pem";

    private static final String PEM_WITH_CERT = "/priv-with-cert.pem";

    // Pinned x5t of priv-with-cert.pem's leaf certificate DER, computed independently of production via:
    //   openssl x509 -in src/test/resources/priv-with-cert.pem -outform DER | openssl dgst -sha1 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    // Re-labelling the certificate block (X509 CERTIFICATE / TRUSTED CERTIFICATE) leaves the DER bytes unchanged, so both parameterizations share this thumbprint.
    private static final String PINNED_PEM_WITH_CERT_X5T = "1VIruVLp9rHaINhtafJpVjintZw";

    // Pinned x5t of the leaf certificate DER only, independent of any trailing X509_CERT_AUX
    // trust-metadata block. Computed via (against the same cert before `openssl x509 -trustout`
    // appended the aux block):
    //   openssl x509 -in cert.pem -outform DER | openssl dgst -sha1 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    private static final String PINNED_REAL_TRUSTED_CERT_X5T = "5wefWnJb6KKlBM-kN8aBSqolJnc";

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

    @ParameterizedTest
    @ValueSource(strings = { "X509 CERTIFICATE", "TRUSTED CERTIFICATE" })
    void signsWithPrivateKeysOwnPublicKey_whenInlinePemEmbedsLegacyLabelledForeignCertificate(String legacyLabel) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair signingKeyPair = keyPairGenerator.generateKeyPair();
        KeyPair foreignKeyPair = keyPairGenerator.generateKeyPair();

        X509Certificate foreignCertificate = selfSignedCertificate(foreignKeyPair);

        String inlineContent =
            pemEncodePrivateKey(signingKeyPair.getPrivate()) + "\n" + pemEncodeCertificate(foreignCertificate, legacyLabel);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", inlineContent);
        config.put("x509CertificateChain", "NONE");
        config.put("x509CertSha1Thumbprint", false);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());

        SignedJWT signedJWT = SignedJWT.parse((String) captor.getValue());

        assertTrue(
            signedJWT.verify(new RSASSAVerifier((RSAPublicKey) signingKeyPair.getPublic())),
            "the JWT must verify against the public key that corresponds to the signing private key — a legacy-labelled certificate embedded in the PEM must not replace the signing key's own public key"
        );
    }

    @ParameterizedTest
    @ValueSource(strings = { "X509 CERTIFICATE", "TRUSTED CERTIFICATE" })
    void emitsLeafX5tThumbprint_whenInlinePemEmbedsLegacyLabelledSigningCertificate(String legacyLabel) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String fixture = fixtureText(PEM_WITH_CERT);
        String privateKeyBlock = pemBlock(fixture, "PRIVATE KEY");
        X509Certificate signingCertificate = parseCertificate(pemBlock(fixture, "CERTIFICATE"));

        String inlineContent = privateKeyBlock + "\n" + pemEncodeCertificate(signingCertificate, legacyLabel);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", inlineContent);
        config.put("x509CertificateChain", "NONE");
        config.put("x509CertSha1Thumbprint", true);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());

        SignedJWT signedJWT = SignedJWT.parse((String) captor.getValue());

        assertEquals(
            PINNED_PEM_WITH_CERT_X5T,
            signedJWT.getHeader().getX509CertThumbprint().toString(),
            "the x5t header must equal the pinned base64url(SHA-1(DER)) of the signing certificate embedded under the legacy PEM label"
        );
    }

    @Test
    void emitsLeafX5tThumbprint_whenInlinePemEmbedsGenuineTrustedCertificateWithAuxiliaryTrustData() throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String inlineContent = fixtureText(REAL_TRUSTED_CERT_PEM);

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", inlineContent);
        config.put("x509CertificateChain", "NONE");
        config.put("x509CertSha1Thumbprint", true);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());

        SignedJWT signedJWT = SignedJWT.parse((String) captor.getValue());

        assertEquals(
            PINNED_REAL_TRUSTED_CERT_X5T,
            signedJWT.getHeader().getX509CertThumbprint().toString(),
            "x5t must equal the pinned SHA-1 thumbprint of the leaf certificate DER, excluding the trailing " +
            "X509_CERT_AUX trust-metadata block that a genuine OpenSSL trustout-exported TRUSTED CERTIFICATE PEM carries"
        );
    }

    @Test
    void rejectsRequest_whenTrustedCertificateBlockBodyIsNotAValidCertificate() throws Exception {
        String inlineContent =
            pemEncodePrivateKey(selfSignedKeyPair().getPrivate()) +
            "\n-----BEGIN TRUSTED CERTIFICATE-----\nbm90LWEtY2VydA==\n-----END TRUSTED CERTIFICATE-----\n";

        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", "INLINE");
        config.put("content", inlineContent);
        config.put("x509CertificateChain", "NONE");
        config.put("x509CertSha1Thumbprint", true);
        GenerateJwtPolicyConfiguration configuration = mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);

        assertDoesNotThrow(() -> new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain));

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(1)).failWith(captor.capture());
        assertEquals(
            500,
            captor.getValue().statusCode(),
            "a TRUSTED CERTIFICATE block whose body cannot be parsed as a certificate must fail with HTTP 500, not throw uncaught"
        );
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    private static KeyPair selfSignedKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String fixtureText(String resource) throws Exception {
        return Files.readString(new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath());
    }

    private static String pemBlock(String pem, String label) {
        String begin = "-----BEGIN " + label + "-----";
        String end = "-----END " + label + "-----";
        return pem.substring(pem.indexOf(begin), pem.indexOf(end) + end.length());
    }

    private static X509Certificate parseCertificate(String certificatePem) throws Exception {
        return (X509Certificate) CertificateFactory
            .getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(certificatePem.getBytes(StandardCharsets.UTF_8)));
    }

    private static X509Certificate selfSignedCertificate(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Foreign CA");
        Date notBefore = Date.from(Instant.now().minusSeconds(3_600));
        Date notAfter = Date.from(Instant.now().plusSeconds(3_600 * 24 * 365));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(System.nanoTime()),
            notBefore,
            notAfter,
            subject,
            keyPair.getPublic()
        );
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider()).getCertificate(holder);
    }

    private static String pemEncodeCertificate(X509Certificate certificate, String label) throws Exception {
        return (
            "-----BEGIN " +
            label +
            "-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(certificate.getEncoded()) +
            "\n-----END " +
            label +
            "-----\n"
        );
    }

    private static String pemEncodePrivateKey(PrivateKey privateKey) {
        return (
            "-----BEGIN PRIVATE KEY-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(privateKey.getEncoded()) +
            "\n-----END PRIVATE KEY-----\n"
        );
    }
}
