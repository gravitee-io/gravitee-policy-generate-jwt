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

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

class GenerateJwtPolicyNonCrtSigningKeyTest {

    private static final String KEYSTORE_ALIAS = "graviteeio";
    private static final String KEYSTORE_STOREPASS = "graviteeio.my.storepass";
    private static final String KEYSTORE_KEYPASS = "graviteeio.my.keypass";

    // Computed independently of production, via:
    //   keytool -exportcert -alias graviteeio -keystore src/test/resources/graviteeio.jks -storepass graviteeio.my.storepass \
    //     | openssl dgst -sha256 -binary | openssl base64 -A | tr '+/' '-_' | tr -d '='
    private static final String PINNED_GRAVITEEIO_JKS_X5T_S256 = "riIh3M8_l-Sk3Kb51IW2AY_W2RDr-k-KXkUQGKwHiMY";

    // Same command as PINNED_GRAVITEEIO_JKS_X5T_S256, but add "-storetype PKCS12" against graviteeio.p12.
    private static final String PINNED_GRAVITEEIO_P12_X5T_S256 = "n5duAZhFJFeAB3gRvQrNKUsYg63UA3nvffKy1wWsaDo";

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
    @EnumSource(value = KeyResolver.class, names = { "JKS", "PKCS12" })
    void populatesCertificateChainAndThumbprint_whenProviderReturnsNonCrtRsaPrivateKeyForMatchingKeystoreEntry(KeyResolver keyResolver)
        throws Exception {
        String keystoreFile = keyResolver == KeyResolver.JKS ? "/graviteeio.jks" : "/graviteeio.p12";
        String keystorePath = Path.of(getClass().getResource(keystoreFile).toURI()).toString();
        KeyStore.PrivateKeyEntry realPrivateKeyEntry = loadRealPrivateKeyEntry(keyResolver, keystorePath);
        Certificate[] realCertificateChain = realPrivateKeyEntry.getCertificateChain();

        RSAPrivateKey nonCrtSigningKey = nonCrtView((RSAPrivateKey) realPrivateKeyEntry.getPrivateKey());
        assertFalse(
            nonCrtSigningKey instanceof RSAPrivateCrtKey,
            "pre-condition: the provider-returned signing key must NOT expose CRT parameters"
        );
        KeyStore.PrivateKeyEntry nonCrtPrivateKeyEntry = new KeyStore.PrivateKeyEntry(nonCrtSigningKey, realCertificateChain);

        when(configuration.getSignature()).thenReturn(Signature.RSA_RS256);
        when(configuration.isX509CertSha256Thumbprint()).thenReturn(true);
        when(configuration.getX509CertificateChain()).thenReturn(X509CertificateChain.X5C);
        when(configuration.getKeyResolver()).thenReturn(keyResolver);
        when(configuration.getContent()).thenReturn(keystorePath);
        when(configuration.getAlias()).thenReturn(KEYSTORE_ALIAS);
        when(configuration.getStorepass()).thenReturn(KEYSTORE_STOREPASS);
        when(configuration.getKeypass()).thenReturn(KEYSTORE_KEYPASS);

        KeyStore nonCrtKeyStore = mock(KeyStore.class);
        when(nonCrtKeyStore.getCertificateChain(KEYSTORE_ALIAS)).thenReturn(realCertificateChain);
        when(nonCrtKeyStore.getEntry(eq(KEYSTORE_ALIAS), any())).thenReturn(nonCrtPrivateKeyEntry);

        try (MockedStatic<KeyStore> keyStoreStatic = mockStatic(KeyStore.class)) {
            keyStoreStatic.when(() -> KeyStore.getInstance(keyResolver.name())).thenReturn(nonCrtKeyStore);

            GenerateJwtPolicy policy = new GenerateJwtPolicy(configuration);

            policy.onRequest(request, response, executionContext, policyChain);

            String expectedThumbprint = keyResolver == KeyResolver.JKS ? PINNED_GRAVITEEIO_JKS_X5T_S256 : PINNED_GRAVITEEIO_P12_X5T_S256;

            verify(policyChain, times(1)).doNext(request, response);
            verify(policyChain, never()).failWith(any());

            ArgumentCaptor<Object> jwtCaptor = ArgumentCaptor.forClass(Object.class);
            verify(executionContext).setAttribute(eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), jwtCaptor.capture());
            Map<String, Object> header = decodeHeader((String) jwtCaptor.getValue());
            assertEquals(
                expectedThumbprint,
                header.get("x5t#S256"),
                "the emitted x5t#S256 header must equal base64url(SHA-256(DER(leaf cert))) for a non-CRT RSA signing key"
            );

            List<?> x5c = (List<?>) header.get("x5c");
            assertNotNull(x5c, "the x5c header must be present when X509CertificateChain.X5C is configured");
            List<String> expectedX5c = Arrays
                .stream(realCertificateChain)
                .map(GenerateJwtPolicyNonCrtSigningKeyTest::encodeCertificate)
                .collect(Collectors.toList());
            assertEquals(
                expectedX5c,
                x5c,
                "the x5c header must contain the full certificate chain in leaf-first order for a non-CRT RSA signing key"
            );
        }
    }

    private static Map<String, Object> decodeHeader(String jwt) throws Exception {
        String protectedHeader = new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8);
        return JSONObjectUtils.parse(protectedHeader);
    }

    private static String encodeCertificate(Certificate certificate) {
        try {
            return Base64.encode(certificate.getEncoded()).toString();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    private static RSAPrivateKey nonCrtView(RSAPrivateKey realKey) {
        return new RSAPrivateKey() {
            @Override
            public BigInteger getPrivateExponent() {
                return realKey.getPrivateExponent();
            }

            @Override
            public BigInteger getModulus() {
                return realKey.getModulus();
            }

            @Override
            public String getAlgorithm() {
                return realKey.getAlgorithm();
            }

            @Override
            public String getFormat() {
                return realKey.getFormat();
            }

            @Override
            public byte[] getEncoded() {
                return realKey.getEncoded();
            }
        };
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
