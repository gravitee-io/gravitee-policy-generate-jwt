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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.IOUtils;
import com.nimbusds.jose.util.X509CertChainUtils;
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
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import jakarta.xml.bind.DatatypeConverter;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import javax.security.auth.x500.X500Principal;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GenerateJwtPolicy {

    private static final Logger log = LoggerFactory.getLogger(GenerateJwtPolicy.class);

    /**
     * Request attributes
     */
    static final String CONTEXT_ATTRIBUTE_JWT_GENERATED = "jwt.generated";

    /**
     * The associated configuration to this Generate JWT Policy
     */
    private final GenerateJwtPolicyConfiguration configuration;

    /**
     * The key is sha1(keyResolver name + content + alias).
     * The value is the RSA signer resolved from that key material.
     */
    static final Map<String, RSASSASigner> signers = new ConcurrentHashMap<>();

    /**
     * The key is the same content hash used for the signers map.
     * The value is the X.509 certificate chain used for the x5c header,
     * ordered leaf-first. This map is the only source for the x5c header.
     */
    static final Map<String, List<Base64>> certChains = new ConcurrentHashMap<>();

    /**
     * The key is the same content hash used for the signers map.
     * The value is the precomputed SHA-1 x5t thumbprint (Base64URL) of the certificate paired with the signing key,
     * or {@link #NO_LEAF_CERTIFICATE} when the key material carries no such certificate.
     * This map is the only source for the x5t header; certChains is the only source for x5c.
     */
    static final Map<String, Base64URL> leafCertificates = new ConcurrentHashMap<>();

    private static final Base64URL NO_LEAF_CERTIFICATE = new Base64URL("");

    private static final Pattern CERTIFICATE_PEM_BLOCK = Pattern.compile(
        "-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        Pattern.DOTALL
    );

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
                String hash = sha1(cacheKeyMaterial());

                signer = getSigner(hash);

                JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(configuration.getKid());
                if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
                    List<Base64> certChain = certChains.get(hash);
                    if (certChain == null || certChain.isEmpty()) {
                        log.error(
                            "[generate-jwt] x5c certificate chain requested but no certificate chain is available for resolver {} — request rejected.",
                            configuration.getKeyResolver().name()
                        );
                        policyChain.failWith(PolicyResult.failure("Unable to generate JWT token"));
                        return;
                    }
                    builder.x509CertChain(certChain);
                }
                if (configuration.isX509CertSha1Thumbprint()) {
                    Base64URL leafCertificate = leafCertificates.get(hash);
                    if (leafCertificate == null || leafCertificate.equals(NO_LEAF_CERTIFICATE)) {
                        log.error(
                            "[generate-jwt] x5t toggle enabled but no certificate is available for resolver {} — request rejected.",
                            configuration.getKeyResolver().name()
                        );
                        policyChain.failWith(PolicyResult.failure("Unable to generate JWT token"));
                        return;
                    }
                    builder.x509CertThumbprint(leafCertificate);
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
        } catch (IOException ex) {
            log.error("Unable to generate JWT token: unable to read key material", ex);
            policyChain.failWith(PolicyResult.failure("Unable to generate JWT token"));
        } catch (KeyStoreException | CertificateException ex) {
            log.error("Unable to generate JWT token: invalid key material", ex);
            policyChain.failWith(PolicyResult.failure("Unable to generate JWT token"));
        } catch (JOSEException ex) {
            log.error("Unable to generate JWT token: invalid key material or signing error", ex);
            policyChain.failWith(PolicyResult.failure("Unable to generate JWT token"));
        } catch (Exception ex) {
            log.error("Unable to generate JWT token: unexpected error not handled by a dedicated catch", ex);
            policyChain.failWith(PolicyResult.failure("Unable to generate JWT token"));
        }
    }

    private RSASSASigner getSigner(String hash) throws Exception {
        RSASSASigner signer = signers.get(hash);
        if (signer == null) {
            // Load
            switch (configuration.getKeyResolver()) {
                case PEM:
                    String pem = IOUtils.readInputStreamToString(readFile(), Charset.defaultCharset());
                    RSAKey pemKey = parseRsaKey(pem);

                    addLeafCertificate(hash, pem, pemKey);

                    signer = new RSASSASigner(pemKey);
                    break;
                case JKS:
                    KeyStore keyStore = getInstance("JKS");

                    if (configuration.getStorepass() != null) {
                        keyStore.load(readFile(), configuration.getStorepass().toCharArray());
                    }

                    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                        configuration.getAlias(),
                        new KeyStore.PasswordProtection(configuration.getKeypass().toCharArray())
                    );

                    if (configuration.getStorepass() != null) {
                        addCertificateChain(hash, keyStore, configuration, pkEntry.getPrivateKey());
                    }

                    signer = new RSASSASigner(pkEntry.getPrivateKey(), true);
                    break;
                case PKCS12:
                    keyStore = getInstance("PKCS12");

                    if (configuration.getStorepass() != null) {
                        keyStore.load(readFile(), configuration.getStorepass().toCharArray());
                    }

                    pkEntry =
                        (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                            configuration.getAlias(),
                            new KeyStore.PasswordProtection(configuration.getStorepass().toCharArray())
                        );

                    if (configuration.getStorepass() != null) {
                        addCertificateChain(hash, keyStore, configuration, pkEntry.getPrivateKey());
                    }

                    signer = new RSASSASigner(pkEntry.getPrivateKey(), true);

                    break;
                case INLINE:
                    RSAKey inlineKey = parseRsaKey(configuration.getContent());

                    addLeafCertificate(hash, configuration.getContent(), inlineKey);

                    signer = new RSASSASigner(inlineKey);
                    break;
                default:
                    break;
            }

            signers.put(hash, signer);
        }

        return signer;
    }

    private static RSAKey parseRsaKey(String pemContent) throws JOSEException {
        return (RSAKey) JWK.parseFromPEMEncodedObjects(CERTIFICATE_PEM_BLOCK.matcher(pemContent).replaceAll(""));
    }

    private void addCertificateChain(String hash, KeyStore keyStore, GenerateJwtPolicyConfiguration configuration, PrivateKey signingKey)
        throws KeyStoreException, NoSuchAlgorithmException {
        Certificate[] certificateChain = keyStore.getCertificateChain(configuration.getAlias());
        if (certificateChain == null || certificateChain.length == 0) {
            if (configuration.isX509CertSha1Thumbprint()) {
                log.error(
                    "[generate-jwt] x5t toggle enabled but no certificate chain is available for resolver {} — thumbprint cannot be computed.",
                    configuration.getKeyResolver().name()
                );
            }
            if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
                log.error(
                    "[generate-jwt] x5c certificate chain requested but no certificate chain is available for resolver {} — the request will be rejected.",
                    configuration.getKeyResolver().name()
                );
            }
            certChains.put(hash, List.of());
            leafCertificates.put(hash, NO_LEAF_CERTIFICATE);
            return;
        }

        if (!leafMatchesSigningKey(certificateChain[0], signingKey)) {
            if (configuration.isX509CertSha1Thumbprint()) {
                log.error(
                    "[generate-jwt] x5t toggle enabled but the keystore certificate chain leaf does not match the signing key for resolver {} — thumbprint cannot be computed.",
                    configuration.getKeyResolver().name()
                );
            }
            if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
                log.error(
                    "[generate-jwt] x5c certificate chain requested but the keystore certificate chain leaf does not match the signing key for resolver {} — the request will be rejected.",
                    configuration.getKeyResolver().name()
                );
            }
            certChains.put(hash, List.of());
            leafCertificates.put(hash, NO_LEAF_CERTIFICATE);
            return;
        }

        List<Base64> certChain;
        try {
            certChain = new ArrayList<>(certificateChain.length);
            for (Certificate certificate : certificateChain) {
                certChain.add(Base64.encode(certificate.getEncoded()));
            }
        } catch (CertificateEncodingException ex) {
            log.error(
                "[generate-jwt] Failed to encode the keystore certificate chain for resolver {}.",
                configuration.getKeyResolver().name(),
                ex
            );
            certChains.put(hash, List.of());
            leafCertificates.put(hash, NO_LEAF_CERTIFICATE);
            return;
        }

        certChains.put(hash, certChain);
        leafCertificates.put(hash, computeX5t(certChain.get(0).decode()));
    }

    private void addLeafCertificate(String hash, String pemContent, RSAKey signingKey) throws JOSEException, NoSuchAlgorithmException {
        List<X509Certificate> certificates;
        try {
            certificates = X509CertChainUtils.parse(pemContent);
        } catch (CertificateException | IOException ex) {
            log.error(
                "[generate-jwt] Failed to parse the certificate block of the key material for resolver {}.",
                configuration.getKeyResolver().name(),
                ex
            );
            certChains.put(hash, List.of());
            leafCertificates.put(hash, NO_LEAF_CERTIFICATE);
            return;
        }

        X509Certificate signingCertificate = findSigningCertificate(certificates, signingKey);
        if (signingCertificate == null) {
            certChains.put(hash, List.of());
            leafCertificates.put(hash, NO_LEAF_CERTIFICATE);
            return;
        }

        List<X509Certificate> orderedCertificates = orderCertificateChain(signingCertificate, certificates);
        try {
            List<Base64> certChain = new ArrayList<>(orderedCertificates.size());
            for (X509Certificate certificate : orderedCertificates) {
                certChain.add(Base64.encode(certificate.getEncoded()));
            }
            certChains.put(hash, certChain);
            leafCertificates.put(hash, computeX5t(signingCertificate.getEncoded()));
        } catch (CertificateEncodingException ex) {
            log.error(
                "[generate-jwt] Failed to encode the certificate chain of the key material for resolver {}.",
                configuration.getKeyResolver().name(),
                ex
            );
            certChains.put(hash, List.of());
            leafCertificates.put(hash, NO_LEAF_CERTIFICATE);
        }
    }

    private static List<X509Certificate> orderCertificateChain(X509Certificate signingCertificate, List<X509Certificate> certificates) {
        List<X509Certificate> remaining = new ArrayList<>(certificates);
        remaining.remove(signingCertificate);

        List<X509Certificate> ordered = new ArrayList<>(certificates.size());
        ordered.add(signingCertificate);

        X509Certificate current = signingCertificate;
        while (!remaining.isEmpty()) {
            X500Principal currentIssuer = current.getIssuerX500Principal();
            X509Certificate issuer = remaining
                .stream()
                .filter(candidate -> candidate.getSubjectX500Principal().equals(currentIssuer))
                .findFirst()
                .orElse(null);
            if (issuer == null) {
                break;
            }
            ordered.add(issuer);
            remaining.remove(issuer);
            current = issuer;
        }
        // Any certificate whose issuer linkage couldn't be resolved (unrelated or malformed bundle)
        // is appended as-is rather than dropped, so x5c degrades gracefully instead of losing data.
        ordered.addAll(remaining);
        return ordered;
    }

    private X509Certificate findSigningCertificate(List<X509Certificate> certificates, RSAKey signingKey) throws JOSEException {
        RSAPublicKey signingPublicKey = signingKey.toRSAPublicKey();
        for (X509Certificate certificate : certificates) {
            if (certificate.getPublicKey() instanceof RSAPublicKey) {
                RSAPublicKey certificatePublicKey = (RSAPublicKey) certificate.getPublicKey();
                if (publicKeysMatch(certificatePublicKey, signingPublicKey)) {
                    return certificate;
                }
            }
        }
        return null;
    }

    private static boolean leafMatchesSigningKey(Certificate leafCertificate, PrivateKey signingKey) {
        if (!(leafCertificate.getPublicKey() instanceof RSAPublicKey) || !(signingKey instanceof RSAPrivateCrtKey)) {
            return false;
        }
        RSAPublicKey leafPublicKey = (RSAPublicKey) leafCertificate.getPublicKey();
        RSAPrivateCrtKey signingCrtKey = (RSAPrivateCrtKey) signingKey;
        return (
            leafPublicKey.getModulus().equals(signingCrtKey.getModulus()) &&
            leafPublicKey.getPublicExponent().equals(signingCrtKey.getPublicExponent())
        );
    }

    private static boolean publicKeysMatch(RSAPublicKey a, RSAPublicKey b) {
        return a.getModulus().equals(b.getModulus()) && a.getPublicExponent().equals(b.getPublicExponent());
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

    private static Base64URL computeX5t(byte[] leafCertDer) throws NoSuchAlgorithmException {
        // SHA-1 is mandated here by RFC 7515 section 4.1.7 for the x5t header value, not a general-purpose hash choice.
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        return Base64URL.encode(digest.digest(leafCertDer));
    }

    /**
     * Identifies the resolved key material; sha1() of this is the actual signer/certificate cache
     * key. Must include the key resolver and alias, not just content, since a single keystore file
     * can hold multiple aliases.
     */
    private String cacheKeyMaterial() {
        String keyResolver = configuration.getKeyResolver() == null ? "" : configuration.getKeyResolver().name();
        String content = configuration.getContent() == null ? "" : configuration.getContent();
        String alias = configuration.getAlias() == null ? "" : configuration.getAlias();
        return sha1(keyResolver) + "." + sha1(content) + "." + sha1(alias);
    }

    public String sha1(String input) {
        String sha1 = null;
        try {
            MessageDigest msdDigest = MessageDigest.getInstance("SHA-1");
            msdDigest.update(input.getBytes(StandardCharsets.UTF_8));
            sha1 = DatatypeConverter.printHexBinary(msdDigest.digest());
        } catch (NoSuchAlgorithmException ignored) {}
        return sha1;
    }
}
