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

import static java.security.KeyStore.*;

import com.google.common.primitives.Bytes;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.gravitee.common.utils.UUID;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import jakarta.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GenerateJwtPolicy {

    /**
     * Request attributes
     */
    static final String CONTEXT_ATTRIBUTE_JWT_GENERATED = "jwt.generated";

    /**
     * The associated configuration to this Generate JWT Policy
     */
    private final GenerateJwtPolicyConfiguration configuration;

    /**
     * The key is the reference to the file.
     * The value is the loaded signer.
     */
    private static final Map<String, RSASSASigner> signers = new HashMap<>();

    /**
     * The encoded certificate chain used for the x5c header
     */
    private static List<Base64> certificateChain = new ArrayList<>();

    /**
     * Create a new Generate JWT Policy instance based on its associated configuration
     *
     * @param configuration the associated configuration to the new Generate JWT Policy instance
     */
    public GenerateJwtPolicy(GenerateJwtPolicyConfiguration configuration) {
        this.configuration = configuration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        try {
            JWSSigner signer = null;
            JWSHeader jwsHeader = null;

            if (configuration.getSignature() == null || configuration.getSignature() == Signature.RSA_RS256) {
                String hash = sha1(configuration.getContent());

                signer = getSigner(hash);

                JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(configuration.getKid());
                if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
                    builder.x509CertChain(certificateChain);
                }
                jwsHeader = builder.build();
            } else if (
                configuration.getSignature() == Signature.HMAC_HS256 ||
                configuration.getSignature() == Signature.HMAC_HS384 ||
                configuration.getSignature() == Signature.HMAC_HS512
            ) {
                jwsHeader = new JWSHeader.Builder(configuration.getSignature().getAlg()).keyID(configuration.getKid()).build();

                if (configuration.getSecretBase64Encoded()) {
                    signer = new MACSigner(java.util.Base64.getDecoder().decode(configuration.getContent()));
                } else {
                    signer = new MACSigner(configuration.getContent().getBytes(StandardCharsets.UTF_8));
                }
            }

            JWTClaimsSet claimsSet = buildClaims(executionContext);
            SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsSet);

            signedJWT.sign(signer);

            String jwt = signedJWT.serialize();
            executionContext.setAttribute(CONTEXT_ATTRIBUTE_JWT_GENERATED, jwt);

            policyChain.doNext(request, response);
        } catch (Exception ex) {
            policyChain.failWith(PolicyResult.failure("Unable to generate JWT token: " + ex.getMessage()));
        }
    }

    private RSASSASigner getSigner(String hash) throws Exception {
        RSASSASigner signer = signers.get(hash);
        if (signer == null) {
            // Load
            switch (configuration.getKeyResolver()) {
                case PEM:
                    String pem = IOUtils.readInputStreamToString(readFile(), Charset.defaultCharset());

                    signer = new RSASSASigner((RSAKey) JWK.parseFromPEMEncodedObjects(pem));
                    break;
                case JKS:
                    KeyStore keyStore = getInstance("JKS");

                    if (configuration.getStorepass() != null) {
                        keyStore.load(readFile(), configuration.getStorepass().toCharArray());
                        addCertificateChain(keyStore, configuration);
                    }

                    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                        configuration.getAlias(),
                        new KeyStore.PasswordProtection(configuration.getKeypass().toCharArray())
                    );

                    signer = new RSASSASigner(pkEntry.getPrivateKey(), true);
                    break;
                case PKCS12:
                    keyStore = getInstance("PKCS12");

                    if (configuration.getStorepass() != null) {
                        keyStore.load(readFile(), configuration.getStorepass().toCharArray());
                        addCertificateChain(keyStore, configuration);
                    }

                    pkEntry =
                        (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                            configuration.getAlias(),
                            new KeyStore.PasswordProtection(configuration.getStorepass().toCharArray())
                        );

                    signer = new RSASSASigner(pkEntry.getPrivateKey(), true);

                    break;
                case INLINE:
                    // Create RSA-signer with the private key
                    signer = new RSASSASigner((RSAKey) JWK.parseFromPEMEncodedObjects(configuration.getContent()));
                    break;
                default:
                    break;
            }

            signers.put(hash, signer);
        }

        return signer;
    }

    private void addCertificateChain(KeyStore keyStore, GenerateJwtPolicyConfiguration configuration) throws KeyStoreException {
        certificateChain =
            Arrays
                .stream(keyStore.getCertificateChain(configuration.getAlias()))
                .map(c -> {
                    try {
                        return Base64.encode(c.getEncoded());
                    } catch (CertificateEncodingException ex) {
                        throw new IllegalArgumentException("Failed to encode certificate.", ex);
                    }
                })
                .collect(Collectors.toList());
    }

    private JWTClaimsSet buildClaims(ExecutionContext executionContext) {
        // Prepare JWT with claims set
        JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder();

        // Issuer time
        Instant issuerTime = Instant.now();
        claimsSet.issueTime(Date.from(issuerTime));

        // JTI / JWT ID
        String jti = templatizeString(executionContext, configuration.getId());
        if (jti == null || jti.isEmpty()) {
            claimsSet.jwtID(UUID.random().toString());
        } else {
            claimsSet.jwtID(jti);
        }

        // Audience
        if (configuration.getAudiences() != null) {
            if (configuration.getAudiences().size() == 1) {
                String aud = templatizeString(executionContext, configuration.getAudiences().get(0));
                claimsSet.audience(aud);
            } else {
                List<String> audiences = configuration
                    .getAudiences()
                    .stream()
                    .map(aud -> templatizeString(executionContext, aud))
                    .collect(Collectors.toList());
                claimsSet.audience(audiences);
            }
        }

        // Subject
        String subject = templatizeString(executionContext, configuration.getSubject());
        if (subject != null && !subject.isEmpty()) {
            claimsSet.subject(subject);
        }

        // Issuer
        String issuer = templatizeString(executionContext, configuration.getIssuer());
        if (issuer != null && !issuer.isEmpty()) {
            claimsSet.issuer(issuer);
        }

        // Expires in
        if (configuration.getExpiresIn() > 0) {
            Instant expiresIn = issuerTime.plus(configuration.getExpiresIn(), ChronoUnit.valueOf(configuration.getExpiresInUnit().name()));

            claimsSet.expirationTime(Date.from(expiresIn));
        }

        // Custom claims
        if (configuration.getCustomClaims() != null && !configuration.getCustomClaims().isEmpty()) {
            configuration
                .getCustomClaims()
                .forEach(claim -> claimsSet.claim(claim.getName(), templatizeObject(executionContext, claim.getValue())));
        }
        return claimsSet.build();
    }

    private Object templatizeObject(ExecutionContext executionContext, String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        return executionContext.getTemplateEngine().getValue(value, Object.class);
    }

    private String templatizeString(ExecutionContext executionContext, String value) {
        if (value == null || value.isEmpty()) {
            return value;
        }

        return executionContext.getTemplateEngine().convert(value);
    }

    private InputStream readFile() throws FileNotFoundException {
        return new FileInputStream(configuration.getContent());
    }

    public String sha1(String input) {
        String sha1 = null;
        try {
            MessageDigest msdDigest = MessageDigest.getInstance("SHA-1");
            msdDigest.update(input.getBytes(Charset.defaultCharset()), 0, input.length());
            sha1 = DatatypeConverter.printHexBinary(msdDigest.digest());
        } catch (NoSuchAlgorithmException ignored) {}
        return sha1;
    }
}
