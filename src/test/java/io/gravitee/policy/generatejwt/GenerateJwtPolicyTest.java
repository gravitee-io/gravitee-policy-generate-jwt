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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.common.utils.UUID;
import io.gravitee.el.TemplateEngine;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.policy.generatejwt.model.Claim;
import io.gravitee.reporter.api.http.Metrics;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.stubbing.Answer;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import static java.security.KeyStore.getInstance;
import static org.mockito.Mockito.*;

/**
 *
 * graviteeio.jks and graviteeio.p12 has been generated using the following commands:
 *
 * > keytool -genkey -alias graviteeio -keyalg RSA -keysize 512 -validity 1825 -keystore "graviteeio.jks" -storetype JKS -dname "CN=www.gravitee.io,OU=Gravitee,O=Gravitee" -keypass graviteeio.my.keypass -storepass graviteeio.my.storepass
 * > keytool -genkey -alias graviteeio -keyalg RSA -keysize 512 -validity 1825 -keystore "graviteeio.p12" -storetype PKCS12 -dname "CN=www.gravitee.io,OU=Gravitee,O=Gravitee" -storepass graviteeio.my.storepass
 *
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GenerateJwtPolicyTest {

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

    @Before
    public void init() {
        MockitoAnnotations.initMocks(this);
        when(request.metrics()).thenReturn(Metrics.on(System.currentTimeMillis()).build());
        when(executionContext.getTemplateEngine()).thenReturn(templateEngine);
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.INLINE);

        when(templateEngine.convert(anyString())).thenAnswer(invMock -> invMock.getArgument(0));
        when(templateEngine.getValue(anyString(), any())).thenAnswer(invMock -> invMock.getArgument(0));
    }

    @Test
    public void shouldFail_rs256_withEmptyPemCertificate() throws Exception {
        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFail_rs256_withInvalidPemCertificate() throws Exception {
        when(configuration.getContent()).thenReturn("an invalid PEM certificate");

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFail_hs256_withEmptySharedSecret() throws Exception {
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFail_hs256_withInvalidSharedSecret() throws Exception {
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.getContent()).thenReturn("an invalid shared secret");

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldSuccess_rs256_withEmptyKid() throws Exception {
        when(configuration.getContent()).thenReturn(loadResource("/priv.pem"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.RS256
                                        && jwsHeader.getKeyID() == null;
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_hs256_withEmptyKid() throws Exception {
        // Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.getContent()).thenReturn(new String(sharedSecret));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.HS256
                                        && jwsHeader.getKeyID() == null;
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_rs256_withKid() throws Exception {
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getContent()).thenReturn(loadResource("/priv.pem"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.RS256
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_rs256_pemResolver() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.PEM);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getContent()).thenReturn(getFile("/priv.pem"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.RS256
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_jksResolver() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.JKS);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getAlias()).thenReturn("graviteeio");
        when(configuration.getStorepass()).thenReturn("graviteeio.my.storepass");
        when(configuration.getKeypass()).thenReturn("graviteeio.my.keypass");
        when(configuration.getContent()).thenReturn(getFile("/graviteeio.jks"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.RS256
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldFail_jksResolver_invalidFile() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.JKS);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getContent()).thenReturn("/an-invalid-file.jks");

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFail_jksResolver_emptyAlias() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.JKS);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getContent()).thenReturn(getFile("/graviteeio.jks"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFail_jksResolver_emptyStorepass() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.JKS);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getAlias()).thenReturn("graviteeio");

        when(configuration.getContent()).thenReturn(getFile("/graviteeio.jks"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldFail_pkcs12Resolver_emptyAlias() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.PKCS12);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getContent()).thenReturn(getFile("/graviteeio-dummy.p12"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldSuccess_pkcs12Resolver() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.PKCS12);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getAlias()).thenReturn("graviteeio");
        when(configuration.getStorepass()).thenReturn("graviteeio.my.storepass");
        when(configuration.getContent()).thenReturn(getFile("/graviteeio.p12"));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.RS256
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);
    }

    @Test
    public void shouldFail_pkcs12Resolver_invalidFile() throws Exception {
        when(configuration.getKeyResolver()).thenReturn(KeyResolver.PKCS12);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getContent()).thenReturn("/an-invalid-file.jks");

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).failWith(any(PolicyResult.class));
    }

    @Test
    public void shouldSuccess_hs256_withKid() throws Exception {
        // Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.getContent()).thenReturn(new String(sharedSecret));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.HS256
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_hs384_withKid() throws Exception {
        // Generate random 384-bit (48-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[48];
        random.nextBytes(sharedSecret);

        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS384);
        when(configuration.getContent()).thenReturn(new String(sharedSecret));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.HS384
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_hs512_withKid() throws Exception {
        // Generate random 512-bit (64-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[64];
        random.nextBytes(sharedSecret);

        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS512);
        when(configuration.getContent()).thenReturn(new String(sharedSecret));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.HS512
                                        && jwsHeader.getKeyID().equals("my-kid");
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_hs256_withJti() throws Exception {
        String jti = UUID.random().toString();

        // Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        when(configuration.getId()).thenReturn(jti);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.getContent()).thenReturn(new String(sharedSecret));

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.HS256
                                && jwsHeader.getKeyID().equals("my-kid")
                                && signedJWT.getJWTClaimsSet().getJWTID().equals(jti);
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    @Test
    public void shouldSuccess_hs256_withCustomClaims() throws Exception {
        String jti = UUID.random().toString();

        // Generate random 256-bit (32-byte) shared secret
        SecureRandom random = new SecureRandom();
        byte[] sharedSecret = new byte[32];
        random.nextBytes(sharedSecret);

        List<Claim> claims = new ArrayList<>();
        claims.add(new Claim("claim1", "claim1-value"));
        claims.add(new Claim("claim2", "claim2-value"));
        claims.add(new Claim("claim3", "elReturningNumber"));

        when(configuration.getCustomClaims()).thenReturn(claims);
        when(configuration.getId()).thenReturn(jti);
        when(configuration.getKid()).thenReturn("my-kid");
        when(configuration.getSignature()).thenReturn(Signature.HMAC_HS256);
        when(configuration.getContent()).thenReturn(new String(sharedSecret));
        when(templateEngine.getValue("elReturningNumber", Object.class)).thenReturn(12345L);

        new GenerateJwtPolicy(configuration).onRequest(request, response, executionContext, policyChain);

        verify(policyChain, times(1)).doNext(request, response);
        verify(executionContext, times(1)).setAttribute(
                eq(GenerateJwtPolicy.CONTEXT_ATTRIBUTE_JWT_GENERATED), argThat((ArgumentMatcher<String>) jwt -> {
                    try {
                        SignedJWT signedJWT = SignedJWT.parse(jwt);
                        JWSHeader jwsHeader = signedJWT.getHeader();

                        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
                        return
                                jwsHeader.getAlgorithm() == JWSAlgorithm.HS256
                                        && jwsHeader.getKeyID().equals("my-kid")
                                        && claimsSet.getJWTID().equals(jti)
                                        && claimsSet.getStringClaim("claim1").equals("claim1-value")
                                        && claimsSet.getStringClaim("claim2").equals("claim2-value")
                                        && claimsSet.getClaim("claim3").equals(12345L);
                    } catch (Exception ex) {
                        return false;
                    }
                }));
    }

    private String getFile(String resource) throws Exception {
        return new File(GenerateJwtPolicy.class.getResource(resource).toURI()).getCanonicalPath();
    }

    private String loadResource(String resource) throws IOException {
        InputStream stream = GenerateJwtPolicy.class.getResourceAsStream(resource);
        return IOUtils.readInputStreamToString(stream, Charset.defaultCharset());
    }
}
