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

import static io.gravitee.policy.generatejwt.X5cTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

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
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

class GenerateJwtPolicyX5cGracefulDegradeTest {

    private static final String HMAC_SECRET_512_BITS = "0123456789012345678901234567890123456789012345678901234567890123";
    private static final String KEYSTORE_ALIAS = "graviteeio";
    private static final String KEYSTORE_STOREPASS = "graviteeio.my.storepass";
    private static final String KEYSTORE_KEYPASS = "graviteeio.my.keypass";
    private static final String RS256 = "RS256";
    private static final String DEFAULT_ISSUER = "urn://gravitee-api-gw";

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
        assertEquals(
            Map.of(HEADER_ALG, signature.getAlg().getName()),
            decodeHeader(jwtCaptor.getValue()),
            "an HMAC signature carries no certificate, so the protected header must carry alg only — no x5c member at all"
        );
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { RESOLVER_JKS, RESOLVER_PKCS12 })
    void x5cOmittedAndRequestProceeds_whenKeystoreAliasHasNoCertificateChain(KeyResolver keyResolver) throws Exception {
        String content = chainlessKeyMaterial(keyResolver);
        KeyStore chainlessKeyStore = chainlessKeyStore(keyResolver, content);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.isX509CertSha1Thumbprint()).thenReturn(false);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(false);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(content);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(chainlessKeyStore);

            new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);
        }

        verify(policyChain, never()).failWith(any());
        verify(policyChain).doNext(request, response);
        ArgumentCaptor<String> jwtCaptor = ArgumentCaptor.forClass(String.class);
        verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
        assertEquals(
            Map.of(HEADER_ALG, RS256),
            decodeHeader(jwtCaptor.getValue()),
            "every keystore resolver must reach the same outcome when the alias carries no certificate chain: the token is issued with a protected header carrying alg only — no x5c member at all"
        );
    }

    private static Stream<Arguments> unresolvableChainCases() throws Exception {
        String noCertificatePem = fixtureText(PEM_NO_CERT);
        String mismatchedPem = noCertificatePem + "\n" + certificateBlock(PEM_WITH_CERT);

        return Stream.of(
            Arguments.of("inlineContentHasNoCertificateBlock", KeyResolver.INLINE, noCertificatePem, false),
            Arguments.of("pemFileHasNoCertificateBlock", KeyResolver.PEM, writeTempPem(noCertificatePem), false),
            Arguments.of("inlineCertificateDoesNotMatchSigningKey", KeyResolver.INLINE, mismatchedPem, false),
            Arguments.of("pemFileCertificateDoesNotMatchSigningKey", KeyResolver.PEM, writeTempPem(mismatchedPem), false),
            // Warm-cache variant: an earlier x5t-only request already populated certChains for this key
            // material, so the x5c request never re-enters addLeafCertificate.
            Arguments.of(
                "inlineCertificateDoesNotMatchSigningKeyOnCachePrimedByThumbprintOnlyRequest",
                KeyResolver.INLINE,
                mismatchedPem,
                true
            )
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unresolvableChainCases")
    void x5cOmittedAndRequestProceeds_whenX5cRequestedButCertificateChainCannotBeResolved(
        String caseName,
        KeyResolver keyResolver,
        String content,
        boolean primeCacheWithThumbprintOnlyRequest
    ) throws Exception {
        if (primeCacheWithThumbprintOnlyRequest) {
            new GenerateJwtPolicy(rsaConfiguration(keyResolver, content, X509_CERTIFICATE_CHAIN_NONE, true, false))
                .onRequest(request, response, executionContext, policyChain);
            clearInvocations(policyChain, executionContext);
        }

        new GenerateJwtPolicy(rsaConfiguration(keyResolver, content, X509_CERTIFICATE_CHAIN_X5C, false, false))
            .onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        String jwt = (String) captor.getValue();

        assertEquals(
            DEFAULT_ISSUER,
            SignedJWT.parse(jwt).getJWTClaimsSet().getIssuer(),
            "the token must still be issued and signed when the chain cannot be resolved — case: " + caseName
        );
        assertEquals(
            Map.of(HEADER_ALG, RS256),
            decodeHeader(jwt),
            "the protected header must carry alg only — no x5c member at all — case: " + caseName
        );
    }

    @ParameterizedTest
    @EnumSource(value = KeyResolver.class, names = { RESOLVER_PEM, RESOLVER_INLINE })
    void x5cOmittedAndRequestProceeds_whenX5cRequestedButCertificateBlockCannotBeParsed(KeyResolver keyResolver) throws Exception {
        String validPrivateKeyWithUnparseableCertificateBlock =
            fixtureText(PEM_NO_CERT) + "\n-----BEGIN TRUSTED CERTIFICATE-----\n!!!not-base64!!!\n-----END TRUSTED CERTIFICATE-----\n";
        String content = keyResolver == KeyResolver.PEM
            ? writeTempPem(validPrivateKeyWithUnparseableCertificateBlock)
            : validPrivateKeyWithUnparseableCertificateBlock;

        new GenerateJwtPolicy(rsaConfiguration(keyResolver, content, X509_CERTIFICATE_CHAIN_X5C, false, false))
            .onRequest(request, response, executionContext, policyChain);

        verify(policyChain, never()).failWith(any());
        verify(policyChain, times(1)).doNext(request, response);

        ArgumentCaptor<Object> captor = ArgumentCaptor.forClass(Object.class);
        verify(executionContext, times(1)).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), captor.capture());
        String jwt = (String) captor.getValue();

        assertEquals(
            DEFAULT_ISSUER,
            SignedJWT.parse(jwt).getJWTClaimsSet().getIssuer(),
            "the token must still be issued and signed when the certificate block cannot be parsed"
        );
        assertEquals(
            Map.of(HEADER_ALG, RS256),
            decodeHeader(jwt),
            "the protected header must carry alg only — no x5c member at all — when the certificate block cannot be parsed"
        );
    }

    private static Stream<Arguments> unresolvableChainCasesPerThumbprintToggle() throws Exception {
        // buildRsaHeader returns at the first failing thumbprint gate, so enabling both toggles at
        // once would leave the x5t#S256 gate — which reads its own cache map — never invoked.
        return unresolvableChainCases()
            .flatMap(base -> {
                Object[] fields = base.get();
                return Stream.of(
                    Arguments.of(fields[0] + "_x5tOnly", fields[1], fields[2], fields[3], true, false),
                    Arguments.of(fields[0] + "_x5tS256Only", fields[1], fields[2], fields[3], false, true)
                );
            });
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("unresolvableChainCasesPerThumbprintToggle")
    void requestRejected_whenChainCannotBeResolvedAndThumbprintToggleIsEnabled(
        String caseName,
        KeyResolver keyResolver,
        String content,
        boolean primeCacheWithThumbprintOnlyRequest,
        boolean x509CertSha1Thumbprint,
        boolean x509CertSha256Thumbprint
    ) throws Exception {
        if (primeCacheWithThumbprintOnlyRequest) {
            new GenerateJwtPolicy(rsaConfiguration(keyResolver, content, X509_CERTIFICATE_CHAIN_NONE, true, false))
                .onRequest(request, response, executionContext, policyChain);
            clearInvocations(policyChain, executionContext);
        }

        new GenerateJwtPolicy(
            rsaConfiguration(keyResolver, content, X509_CERTIFICATE_CHAIN_X5C, x509CertSha1Thumbprint, x509CertSha256Thumbprint)
        )
            .onRequest(request, response, executionContext, policyChain);

        ArgumentCaptor<PolicyResult> captor = ArgumentCaptor.forClass(PolicyResult.class);
        verify(policyChain, times(1)).failWith(captor.capture());
        assertEquals(
            500,
            captor.getValue().statusCode(),
            "a thumbprint toggle with no resolvable leaf certificate must still fail closed once x5c degrades gracefully — case: " +
            caseName
        );
        verify(policyChain, never()).doNext(any(), any());
        verify(executionContext, never()).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), any());
    }

    private String chainlessKeyMaterial(KeyResolver keyResolver) throws Exception {
        String keystoreResource = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        return Path.of(getClass().getResource(keystoreResource).toURI()).toString();
    }

    private KeyStore chainlessKeyStore(KeyResolver keyResolver, String keystorePath) throws Exception {
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);
        KeyStore chainlessKeyStore = mock(KeyStore.class);
        when(chainlessKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn((Certificate[]) null);
        when(chainlessKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(realPrivateKeyEntry);
        return chainlessKeyStore;
    }

    private KeyStore.PrivateKeyEntry loadRealPrivateKeyEntry(KeyResolver keyResolver, String keystorePath) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(keyResolver.name());
        try (InputStream inputStream = new FileInputStream(keystorePath)) {
            keyStore.load(inputStream, KEYSTORE_STOREPASS.toCharArray());
        }
        String entryPassword = keyResolver == KeyResolver.JKS ? KEYSTORE_KEYPASS : KEYSTORE_STOREPASS;
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(KEYSTORE_ALIAS, new KeyStore.PasswordProtection(entryPassword.toCharArray()));
    }

    private static String writeTempPem(String pemContent) throws Exception {
        Path target = Files.createTempFile("x5c-pem-", PEM_FILE_SUFFIX);
        target.toFile().deleteOnExit();
        Files.writeString(target, pemContent);
        return target.toAbsolutePath().toString();
    }

    private static String certificateBlock(String resource) throws Exception {
        String pem = fixtureText(resource);
        return pem.substring(pem.indexOf("-----BEGIN CERTIFICATE-----"));
    }
}
