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

import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

class GenerateJwtPolicyX5tFailFastTest {

    private static final String HMAC_SECRET_512_BITS = "0123456789012345678901234567890123456789012345678901234567890123";
    private static final String KEYSTORE_ALIAS = "graviteeio";
    private static final String KEYSTORE_STOREPASS = "graviteeio.my.storepass";
    private static final String KEYSTORE_KEYPASS = "graviteeio.my.keypass";
    private static final String PINNED_PEM_WITH_CERT_X5T = "1VIruVLp9rHaINhtafJpVjintZw";

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
        GenerateJwtPolicy.leafCertificatesSha256.clear();
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(templateEngine.convert(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
        when(templateEngine.getValue(anyString(), any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @AfterEach
    void tearDown() {
        GenerateJwtPolicy.signers.clear();
        GenerateJwtPolicy.certChains.clear();
        GenerateJwtPolicy.leafCertificates.clear();
        GenerateJwtPolicy.leafCertificatesSha256.clear();
    }

    @ParameterizedTest
    @EnumSource(value = Signature.class, names = { "HMAC_HS256", "HMAC_HS384", "HMAC_HS512" })
    void ignoresThumbprintToggleAndSignsNormally_whenHmacSignatureConfiguredWithThumbprintToggleEnabled(Signature signature)
        throws Exception {
        when(configuration.getSignature()).thenReturn(signature);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getContent()).thenReturn(HMAC_SECRET_512_BITS);
        when(configuration.getSecretBase64Encoded()).thenReturn(false);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);
        policy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(2)).doNext(request, response);
        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(executionContext, times(2)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
        Map<String, Object> header = decodeHeader(jwtCaptor.getValue());
        assertFalse(header.containsKey("x5t"), "an HMAC signature carries no certificate, so x5t must be silently ignored");
        assertEquals(Set.of("alg"), header.keySet(), "an HMAC header must carry only the alg member");
    }

    @Test
    void ignoresThumbprintToggleAndSignsNormally_whenHmacConfiguredViaRealConfigurationPojoWithThumbprintToggleEnabled() throws Exception {
        GenerateJwtPolicyConfiguration realConfiguration = new GenerateJwtPolicyConfiguration();
        realConfiguration.setSignature(Signature.HMAC_HS256);
        realConfiguration.setX509CertSha1Thumbprint(true);
        realConfiguration.setContent(HMAC_SECRET_512_BITS);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(realConfiguration);

        policy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain).doNext(request, response);
        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
        Map<String, Object> header = decodeHeader(jwtCaptor.getValue());
        assertFalse(header.containsKey("x5t"), "an HMAC signature carries no certificate, so x5t must be silently ignored");
        assertEquals(Set.of("alg"), header.keySet(), "an HMAC header must carry only the alg member");
    }

    @Test
    void rejectsRequestWith500_whenHmacSecretInvalidAndThumbprintToggleEnabled() {
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getContent()).thenReturn("too-short-secret");
        when(configuration.getSecretBase64Encoded()).thenReturn(false);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);

        assertRejectedWith500(1);
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void rejectsEveryRequestWith500_whenThumbprintToggleEnabledAndNoCertificateIsAvailable(KeyResolver keyResolver) throws Exception {
        Path privateKeyOnlyPem = Path.of(getClass().getResource("/priv.pem").toURI());
        String content = keyResolver == KeyResolver.PEM ? privateKeyOnlyPem.toString() : Files.readString(privateKeyOnlyPem);
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(content);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);
        policy.onRequest(request, response, executionContext, policyChain);

        assertRejectedWith500(2);
    }

    @ParameterizedTest
    @CsvSource({ "JKS, EMPTY_ENTRY", "JKS, MISSING_ENTRY", "PKCS12, EMPTY_ENTRY", "PKCS12, MISSING_ENTRY" })
    void rejectsEveryRequestWith500_whenThumbprintToggleEnabledAndKeystoreYieldsNoLeafCertificate(
        KeyResolver keyResolver,
        String leafCertificateState
    ) throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);
        String hash = policy.cacheKeyMaterial();
        GenerateJwtPolicy.signers.put(hash, new RSASSASigner(loadRealPrivateKeyEntry(keyResolver, keystorePath).getPrivateKey(), true));
        if ("EMPTY_ENTRY".equals(leafCertificateState)) {
            GenerateJwtPolicy.leafCertificates.put(hash, Optional.empty());
        }

        policy.onRequest(request, response, executionContext, policyChain);
        policy.onRequest(request, response, executionContext, policyChain);

        assertRejectedWith500(2);
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void continuesDegraded_whenThumbprintToggleEnabledAndPemContentCarriesNoCertificateBlock(KeyResolver keyResolver) throws Exception {
        Path privateKeyOnlyPem = Path.of(getClass().getResource("/priv.pem").toURI());
        String content = keyResolver == KeyResolver.PEM ? privateKeyOnlyPem.toString() : Files.readString(privateKeyOnlyPem);
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(content);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);

        String hash = policy.cacheKeyMaterial();
        assertNotNull(GenerateJwtPolicy.signers.get(hash), "the signer load must complete despite the missing certificate");
        Optional<Base64URL> leafCertificate = GenerateJwtPolicy.leafCertificates.get(hash);
        assertNotNull(leafCertificate, "the degraded state must record a leaf-certificate entry for the content hash");
        assertTrue(leafCertificate.isEmpty(), "the recorded leaf-certificate entry must be empty");
    }

    @ParameterizedTest
    @CsvSource({ "JKS, NULL_CHAIN", "JKS, EMPTY_CHAIN", "PKCS12, NULL_CHAIN", "PKCS12, EMPTY_CHAIN" })
    void continuesDegraded_whenThumbprintToggleEnabledAndKeystoreCertificateChainIsNullOrEmpty(KeyResolver keyResolver, String chainState)
        throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore chainlessKeyStore = mock(KeyStore.class);
        Certificate[] certificateChain = "NULL_CHAIN".equals(chainState) ? null : new Certificate[0];
        when(chainlessKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(certificateChain);
        when(chainlessKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(chainlessKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);

            String hash = policy.cacheKeyMaterial();
            assertNotNull(GenerateJwtPolicy.signers.get(hash), "the signer load must complete despite the missing certificate chain");
            Optional<Base64URL> leafCertificate = GenerateJwtPolicy.leafCertificates.get(hash);
            assertNotNull(leafCertificate, "the degraded state must record a leaf-certificate entry for the content hash");
            assertTrue(leafCertificate.isEmpty(), "the recorded leaf-certificate entry must be empty");
        }
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void failsWith500ErrorOnFirstRequest_whenChainlessKeystoreDegradedStateRejectsEveryRequestIncludingTheFirst(KeyResolver keyResolver)
        throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore chainlessKeyStore = mock(KeyStore.class);
        when(chainlessKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(null);
        when(chainlessKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(chainlessKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);
            policy.onRequest(request, response, executionContext, policyChain);

            assertRejectedWith500(2);
        }
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void signsNormallyWithoutThumbprint_whenToggleDisabledAndKeystoreCertificateChainIsNull(KeyResolver keyResolver) throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore chainlessKeyStore = mock(KeyStore.class);
        when(chainlessKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(null);
        when(chainlessKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(chainlessKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);

            verify(policyChain, never()).failWith(any());
            verify(policyChain).doNext(request, response);
            ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
            verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            SignedJWT signedJWT = SignedJWT.parse(jwtCaptor.getValue());
            assertNull(signedJWT.getHeader().getX509CertThumbprint(), "no x5t header may be emitted when the toggle is disabled");
        }
    }

    @ParameterizedTest
    @CsvSource({ "JKS, NULL_CHAIN", "JKS, EMPTY_CHAIN", "PKCS12, NULL_CHAIN", "PKCS12, EMPTY_CHAIN" })
    void signsWithoutX5cHeader_whenX5cEnabledWithThumbprintTogglesDisabledAndKeystoreCertificateChainIsNullOrEmpty(
        KeyResolver keyResolver,
        String chainState
    ) throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore chainlessKeyStore = mock(KeyStore.class);
        Certificate[] certificateChain = "NULL_CHAIN".equals(chainState) ? null : new Certificate[0];
        when(chainlessKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(certificateChain);
        when(chainlessKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(chainlessKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);

            verify(policyChain, never()).failWith(any());
            verify(policyChain).doNext(request, response);
            ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
            verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            SignedJWT signedJWT = SignedJWT.parse(jwtCaptor.getValue());
            assertNull(
                signedJWT.getHeader().getX509CertChain(),
                "no x5c header may be emitted when the keystore returns no certificate chain"
            );
        }
    }

    @ParameterizedTest
    @CsvSource({ "JKS, NULL_CHAIN", "JKS, EMPTY_CHAIN", "PKCS12, NULL_CHAIN", "PKCS12, EMPTY_CHAIN" })
    void reOmitsX5cOnWarmRequestWithoutReReadingKeystore_whenX5cEnabledWithThumbprintTogglesDisabledAndKeystoreCertificateChainIsNullOrEmpty(
        KeyResolver keyResolver,
        String chainState
    ) throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore chainlessKeyStore = mock(KeyStore.class);
        Certificate[] certificateChain = "NULL_CHAIN".equals(chainState) ? null : new Certificate[0];
        when(chainlessKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(certificateChain);
        when(chainlessKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(chainlessKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);
            policy.onRequest(request, response, executionContext, policyChain);

            verify(policyChain, never()).failWith(any());
            verify(policyChain, times(2)).doNext(request, response);
            verify(chainlessKeyStore, times(1)).getCertificateChain(KEYSTORE_ALIAS);
            ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
            verify(executionContext, times(2)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            for (String jwt : jwtCaptor.getAllValues()) {
                assertNull(
                    SignedJWT.parse(jwt).getHeader().getX509CertChain(),
                    "no x5c header may be emitted on either the cold or the warm request when the keystore returns no certificate chain"
                );
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "PEM", "INLINE" })
    void stopsSigningAndRejectsWith500_whenThumbprintToggleEnabledAfterCertlessSignerCachedWithToggleOff(KeyResolver keyResolver)
        throws Exception {
        Path privateKeyOnlyPem = Path.of(getClass().getResource("/priv.pem").toURI());
        String content = keyResolver == KeyResolver.PEM ? privateKeyOnlyPem.toString() : Files.readString(privateKeyOnlyPem);
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(content);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);

        verify(policyChain).doNext(request, response);
        verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());

        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);

        policy.onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain).failWith(captor.capture());
        assertEquals(500, captor.getValue().statusCode(), "the rejection after enabling the toggle must carry HTTP 500");
        verify(policyChain, times(1)).doNext(any(), any());
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    @Test
    void keepsDegradedStateIsolatedPerKeyMaterial_whenCertlessAndCertBearingInlineConfigsCoexist() throws Exception {
        String certlessContent = Files.readString(Path.of(getClass().getResource("/priv.pem").toURI()));
        String certBearingContent = Files.readString(Path.of(getClass().getResource("/priv-with-cert.pem").toURI()));
        GenerateJwtPolicyConfiguration certlessConfiguration = mock(GenerateJwtPolicyConfiguration.class);
        when(certlessConfiguration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(certlessConfiguration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(certlessConfiguration.getKeyResolver()).thenReturn(KeyResolver.INLINE);
        when(certlessConfiguration.getContent()).thenReturn(certlessContent);
        GenerateJwtPolicyConfiguration certBearingConfiguration = mock(GenerateJwtPolicyConfiguration.class);
        when(certBearingConfiguration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(certBearingConfiguration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(certBearingConfiguration.getKeyResolver()).thenReturn(KeyResolver.INLINE);
        when(certBearingConfiguration.getContent()).thenReturn(certBearingContent);
        PolicyChain certlessPolicyChain = mock(PolicyChain.class);
        PolicyChain certBearingPolicyChain = mock(PolicyChain.class);
        ExecutionContext certlessExecutionContext = mock(ExecutionContext.class);
        ExecutionContext certBearingExecutionContext = mock(ExecutionContext.class);
        GenerateJwtPolicy certlessPolicy = new GenerateJwtPolicy(certlessConfiguration);
        GenerateJwtPolicy certBearingPolicy = new GenerateJwtPolicy(certBearingConfiguration);

        certlessPolicy.onRequest(request, response, certlessExecutionContext, certlessPolicyChain);
        certBearingPolicy.onRequest(request, response, certBearingExecutionContext, certBearingPolicyChain);
        certlessPolicy.onRequest(request, response, certlessExecutionContext, certlessPolicyChain);

        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(certBearingExecutionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
        verify(certBearingPolicyChain).doNext(request, response);
        verify(certBearingPolicyChain, never()).failWith(any());
        Base64URL x5t = SignedJWT.parse(jwtCaptor.getValue()).getHeader().getX509CertThumbprint();
        assertEquals(
            new Base64URL(PINNED_PEM_WITH_CERT_X5T),
            x5t,
            "the cert-bearing config must emit its own certificate's thumbprint despite the coexisting degraded entry"
        );
        ArgumentCaptor<PolicyResult> rejectionCaptor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(certlessPolicyChain, times(2)).failWith(rejectionCaptor.capture());
        for (PolicyResult result : rejectionCaptor.getAllValues()) {
            assertEquals(500, result.statusCode(), "each rejection must carry HTTP 500");
        }
        verify(certlessPolicyChain, never()).doNext(any(), any());
        verify(certlessExecutionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    @Test
    void failsClosedWith500OnEveryRequestWithoutEmittingToken_whenInlinePemPairsPrivateKeyWithForeignCertificate() throws Exception {
        String privateKeyPem = Files.readString(Path.of(getClass().getResource("/priv.pem").toURI()));
        String foreignCertificatePem = pemEncodedJksLeafCertificate();
        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.INLINE);
        when(configuration.getContent()).thenReturn(privateKeyPem + "\n" + foreignCertificatePem);

        GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

        policy.onRequest(request, response, executionContext, policyChain);
        policy.onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(2)).failWith(captor.capture());
        for (PolicyResult result : captor.getAllValues()) {
            assertEquals(500, result.statusCode(), "each rejection must carry HTTP 500");
        }
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void failsClosedWith500OnEveryRequestWithoutEmittingToken_whenKeystoreCertificateChainLeafDoesNotMatchSigningKey(
        KeyResolver keyResolver
    ) throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);
        Certificate foreignCertificate = foreignLeafCertificate();

        assertFalse(
            Arrays.equals(realPrivateKeyEntry.getCertificate().getPublicKey().getEncoded(), foreignCertificate.getPublicKey().getEncoded()),
            "pre-condition: the keystore chain's leaf certificate must carry a different public key than the resolved signing key"
        );

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(true);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore mismatchedKeyStore = mock(KeyStore.class);
        when(mismatchedKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(new Certificate[] { foreignCertificate });
        when(mismatchedKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(mismatchedKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);
            policy.onRequest(request, response, executionContext, policyChain);

            assertRejectedWith500(2);
        }
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void embedsKeystoreCertificateChainAsX5c_whenLeafDoesNotMatchSigningKeyAndThumbprintTogglesDisabled(KeyResolver keyResolver)
        throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);
        Certificate foreignCertificate = foreignLeafCertificate();
        Certificate[] mismatchedChain = { foreignCertificate, realPrivateKeyEntry.getCertificate() };

        assertFalse(
            Arrays.equals(realPrivateKeyEntry.getCertificate().getPublicKey().getEncoded(), foreignCertificate.getPublicKey().getEncoded()),
            "pre-condition: the keystore chain's leaf certificate must carry a different public key than the resolved signing key"
        );

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore mismatchedKeyStore = mock(KeyStore.class);
        when(mismatchedKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(mismatchedChain);
        when(mismatchedKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(mismatchedKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);

            verify(policyChain, never()).failWith(any());
            verify(policyChain).doNext(request, response);
            ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
            verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            SignedJWT signedJWT = SignedJWT.parse(jwtCaptor.getValue());
            var x5c = signedJWT.getHeader().getX509CertChain();
            assertNotNull(x5c, "x5c must be populated from the keystore chain even though the leaf does not match the signing key");
            assertEquals(mismatchedChain.length, x5c.size(), "x5c must contain every certificate returned by the keystore chain");
            for (int i = 0; i < mismatchedChain.length; i++) {
                assertArrayEquals(
                    mismatchedChain[i].getEncoded(),
                    x5c.get(i).decode(),
                    "x5c entry " + i + " must be the keystore chain certificate, byte-for-byte, in keystore order"
                );
            }
        }
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void emitsHeaderWithOnlyAlgAndX5cMembers_whenLeafDoesNotMatchSigningKeyAndThumbprintTogglesDisabled(KeyResolver keyResolver)
        throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);
        Certificate foreignCertificate = foreignLeafCertificate();
        Certificate[] mismatchedChain = { foreignCertificate, realPrivateKeyEntry.getCertificate() };

        assertFalse(
            Arrays.equals(realPrivateKeyEntry.getCertificate().getPublicKey().getEncoded(), foreignCertificate.getPublicKey().getEncoded()),
            "pre-condition: the keystore chain's leaf certificate must carry a different public key than the resolved signing key"
        );

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore mismatchedKeyStore = mock(KeyStore.class);
        when(mismatchedKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(mismatchedChain);
        when(mismatchedKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(mismatchedKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);

            verify(policyChain, never()).failWith(any());
            verify(policyChain).doNext(request, response);
            ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
            verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            Map<String, Object> header = decodeHeader(jwtCaptor.getValue());
            assertEquals(
                Set.of("alg", "x5c"),
                header.keySet(),
                "the leaf-mismatch header must carry exactly alg and x5c — no x5t/x5t#S256 member may leak in when the thumbprint toggles are off"
            );
        }
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void reEmitsCachedX5cOnWarmRequestWithoutReReadingKeystore_whenLeafDoesNotMatchSigningKeyAndThumbprintTogglesDisabled(
        KeyResolver keyResolver
    ) throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);
        Certificate foreignCertificate = foreignLeafCertificate();
        Certificate[] mismatchedChain = { foreignCertificate, realPrivateKeyEntry.getCertificate() };

        assertFalse(
            Arrays.equals(realPrivateKeyEntry.getCertificate().getPublicKey().getEncoded(), foreignCertificate.getPublicKey().getEncoded()),
            "pre-condition: the keystore chain's leaf certificate must carry a different public key than the resolved signing key"
        );

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(false);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore mismatchedKeyStore = mock(KeyStore.class);
        when(mismatchedKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(mismatchedChain);
        when(mismatchedKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(mismatchedKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);
            policy.onRequest(request, response, executionContext, policyChain);

            verify(policyChain, never()).failWith(any());
            verify(policyChain, times(2)).doNext(request, response);
            verify(mismatchedKeyStore, times(1)).getCertificateChain(KEYSTORE_ALIAS);
            ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
            verify(executionContext, times(2)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            for (String jwt : jwtCaptor.getAllValues()) {
                var x5c = SignedJWT.parse(jwt).getHeader().getX509CertChain();
                assertNotNull(x5c, "x5c must be re-emitted from the persisted chain cache on both the cold and the warm request");
                assertEquals(mismatchedChain.length, x5c.size(), "x5c must contain every certificate returned by the keystore chain");
                for (int i = 0; i < mismatchedChain.length; i++) {
                    assertArrayEquals(
                        mismatchedChain[i].getEncoded(),
                        x5c.get(i).decode(),
                        "x5c entry " + i + " must be the keystore chain certificate, byte-for-byte, in keystore order"
                    );
                }
            }
        }
    }

    private Map<String, Object> decodeHeader(String jwt) throws Exception {
        String protectedHeader = new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
        return JSONObjectUtils.parse(protectedHeader);
    }

    private Certificate foreignLeafCertificate() throws Exception {
        String keystorePath = Path.of(getClass().getResource("/graviteeio-chain.jks").toURI()).toString();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(keystorePath)) {
            keyStore.load(inputStream, "chain.my.storepass".toCharArray());
        }
        return keyStore.getCertificate("leaf");
    }

    private void assertRejectedWith500(int expectedRejections) {
        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(expectedRejections)).failWith(captor.capture());
        for (PolicyResult result : captor.getAllValues()) {
            assertEquals(500, result.statusCode(), "each rejection must carry HTTP 500");
        }
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    private String pemEncodedJksLeafCertificate() throws Exception {
        String keystorePath = Path.of(getClass().getResource("/graviteeio.jks").toURI()).toString();
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream inputStream = new FileInputStream(keystorePath)) {
            keyStore.load(inputStream, KEYSTORE_STOREPASS.toCharArray());
        }
        byte[] certificateDer = keyStore.getCertificate(KEYSTORE_ALIAS).getEncoded();
        return (
            "-----BEGIN CERTIFICATE-----\n" +
            Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(certificateDer) +
            "\n-----END CERTIFICATE-----\n"
        );
    }

    private KeyStore.PrivateKeyEntry loadRealPrivateKeyEntry(KeyResolver keyResolver, String keystorePath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keyResolver.name());
        try (InputStream inputStream = new FileInputStream(keystorePath)) {
            keyStore.load(inputStream, KEYSTORE_STOREPASS.toCharArray());
        }
        String entryPassword = keyResolver == KeyResolver.JKS ? KEYSTORE_KEYPASS : KEYSTORE_STOREPASS;
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEYSTORE_ALIAS, new KeyStore.PasswordProtection(entryPassword.toCharArray()));
    }
}
