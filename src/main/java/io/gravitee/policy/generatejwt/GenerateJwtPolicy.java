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
import io.gravitee.policy.generatejwt.configuration.X509CertificateChain;
import jakarta.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
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
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
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

    private static final String JWT_GENERATION_FAILURE_MESSAGE = "Unable to generate JWT token";

    /**
     * The associated configuration to this Generate JWT Policy
     */
    private final GenerateJwtPolicyConfiguration configuration;

    /**
     * The key is cacheKeyMaterial(): sha1(keyResolver) + "." + sha1(content) + "." + sha1(alias).
     * The value is the RSA signer resolved from that key material.
     */
    static final Map<String, RSASSASigner> signers = new ConcurrentHashMap<>();

    /**
     * The key is the same cacheKeyMaterial() key used for the signers map.
     * The value is the X.509 certificate chain used for the x5c header,
     * ordered leaf-first. This map is the only source for the x5c header.
     */
    static final Map<String, List<Base64>> certChains = new ConcurrentHashMap<>();

    /**
     * The key is the same cacheKeyMaterial() key used for the signers map.
     * The value is the precomputed SHA-1 x5t thumbprint (Base64URL) of the certificate paired with the signing key,
     * or {@link Optional#empty()} when the key material carries no such certificate.
     * This map is the only source for the x5t header; certChains is the only source for x5c.
     */
    static final Map<String, Optional<Base64URL>> leafCertificates = new ConcurrentHashMap<>();

    /**
     * The key is the same cacheKeyMaterial() key used for the signers map.
     * The value is the precomputed SHA-256 x5t#S256 thumbprint (Base64URL) of the certificate paired with the signing key,
     * or {@link Optional#empty()} when the key material carries no such certificate.
     * This map is the only source for the x5t#S256 header.
     */
    static final Map<String, Optional<Base64URL>> leafCertificatesSha256 = new ConcurrentHashMap<>();

    private static final Pattern CERTIFICATE_PEM_BLOCK = Pattern.compile(
        "-----BEGIN (?:TRUSTED |X509 )?CERTIFICATE-----.*?-----END (?:TRUSTED |X509 )?CERTIFICATE-----",
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
                String hash = cacheKeyMaterial();

                signer = getSigner(hash);

                jwsHeader = buildRsaHeader(hash, policyChain);
                if (jwsHeader == null) {
                    return;
                }
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
            policyChain.failWith(PolicyResult.failure(JWT_GENERATION_FAILURE_MESSAGE));
        } catch (KeyStoreException | CertificateException ex) {
            log.error("Unable to generate JWT token: invalid key material", ex);
            policyChain.failWith(PolicyResult.failure(JWT_GENERATION_FAILURE_MESSAGE));
        } catch (JOSEException ex) {
            log.error("Unable to generate JWT token: invalid key material or signing error", ex);
            policyChain.failWith(PolicyResult.failure(JWT_GENERATION_FAILURE_MESSAGE));
        } catch (Exception ex) {
            log.error(
                "Unable to generate JWT token: UNEXPECTED error not handled by a dedicated catch (exception class: {})",
                ex.getClass().getName(),
                ex
            );
            policyChain.failWith(PolicyResult.failure(JWT_GENERATION_FAILURE_MESSAGE));
        }
    }

    private JWSHeader buildRsaHeader(String hash, PolicyChain policyChain) {
        JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(configuration.getKid());
        if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
            List<Base64> certChain = resolveCertChain(hash, policyChain);
            if (certChain == null) {
                return null;
            }
            builder.x509CertChain(certChain);
        }
        if (configuration.isX509CertSha1Thumbprint()) {
            Base64URL leafCertificate = resolveLeafCertificate(hash, policyChain);
            if (leafCertificate == null) {
                return null;
            }
            builder.x509CertThumbprint(leafCertificate);
        }
        if (configuration.isX509CertSha256Thumbprint()) {
            Base64URL leafCertificateSha256 = resolveLeafCertificateSha256(hash, policyChain);
            if (leafCertificateSha256 == null) {
                return null;
            }
            builder.x509CertSHA256Thumbprint(leafCertificateSha256);
        }
        return builder.build();
    }

    private List<Base64> resolveCertChain(String hash, PolicyChain policyChain) {
        return resolveRequiredHeaderValue(
            certChains,
            hash,
            chain -> !chain.isEmpty(),
            chain -> chain,
            "[generate-jwt] x5c certificate chain requested but no certificate chain is available for resolver {} — request rejected.",
            policyChain
        );
    }

    private Base64URL resolveLeafCertificate(String hash, PolicyChain policyChain) {
        return resolveRequiredHeaderValue(
            leafCertificates,
            hash,
            Optional::isPresent,
            Optional::get,
            "[generate-jwt] x5t toggle enabled but no certificate is available for resolver {} — request rejected.",
            policyChain
        );
    }

    private Base64URL resolveLeafCertificateSha256(String hash, PolicyChain policyChain) {
        return resolveRequiredHeaderValue(
            leafCertificatesSha256,
            hash,
            Optional::isPresent,
            Optional::get,
            "[generate-jwt] x5t#S256 toggle enabled but no certificate is available for resolver {} — request rejected.",
            policyChain
        );
    }

    private <V, R> R resolveRequiredHeaderValue(
        Map<String, V> cache,
        String hash,
        Predicate<V> hasValue,
        Function<V, R> unwrap,
        String errorMessage,
        PolicyChain policyChain
    ) {
        V cached = cache.get(hash);
        if (cached == null || !hasValue.test(cached)) {
            log.error(errorMessage, configuration.getKeyResolver().name());
            policyChain.failWith(PolicyResult.failure(JWT_GENERATION_FAILURE_MESSAGE));
            return null;
        }
        return unwrap.apply(cached);
    }

    private static void clearCertificateCaches(String hash) {
        certChains.put(hash, List.of());
        leafCertificates.put(hash, Optional.empty());
        leafCertificatesSha256.put(hash, Optional.empty());
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
                case PKCS12:
                    if (configuration.getStorepass() == null) {
                        throw new KeyStoreException(
                            "storepass is required for the " + configuration.getKeyResolver().name() + " key resolver"
                        );
                    }

                    var keyStore = getInstance(configuration.getKeyResolver().name());
                    try (var is = readFile()) {
                        keyStore.load(is, configuration.getStorepass().toCharArray());
                    }

                    var pkEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
                        configuration.getAlias(),
                        new KeyStore.PasswordProtection(resolveKeyEntryPassword())
                    );

                    addCertificateChain(hash, keyStore, pkEntry.getPrivateKey());

                    signer = new RSASSASigner(pkEntry.getPrivateKey(), true);
                    break;
                case INLINE:
                    RSAKey inlineKey = parseRsaKey(configuration.getContent());

                    addLeafCertificate(hash, configuration.getContent(), inlineKey);

                    signer = new RSASSASigner(inlineKey);
                    break;
                default:
                    log.error("[generate-jwt] Unsupported key resolver {} — cannot resolve signer.", configuration.getKeyResolver().name());
                    throw new IllegalStateException("Unsupported key resolver: " + configuration.getKeyResolver().name());
            }

            signers.put(hash, signer);
        }

        return signer;
    }

    private char[] resolveKeyEntryPassword() {
        switch (configuration.getKeyResolver()) {
            case JKS:
                return configuration.getKeypass().toCharArray();
            case PKCS12:
                return configuration.getStorepass().toCharArray();
            default:
                throw new IllegalStateException("Unsupported key resolver for entry password: " + configuration.getKeyResolver().name());
        }
    }

    private static RSAKey parseRsaKey(String pemContent) throws JOSEException {
        return (RSAKey) JWK.parseFromPEMEncodedObjects(CERTIFICATE_PEM_BLOCK.matcher(pemContent).replaceAll(""));
    }

    private void logSuppressedChainToggles(String reason) {
        if (configuration.isX509CertSha1Thumbprint()) {
            log.error(
                "[generate-jwt] x5t toggle enabled but {} for resolver {} — thumbprint cannot be computed.",
                reason,
                configuration.getKeyResolver().name()
            );
        }
        if (configuration.isX509CertSha256Thumbprint()) {
            log.error(
                "[generate-jwt] x5t#S256 toggle enabled but {} for resolver {} — thumbprint cannot be computed.",
                reason,
                configuration.getKeyResolver().name()
            );
        }
        if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
            log.error(
                "[generate-jwt] x5c certificate chain requested but {} for resolver {} — the request will be rejected.",
                reason,
                configuration.getKeyResolver().name()
            );
        }
    }

    private void addCertificateChain(String hash, KeyStore keyStore, PrivateKey signingKey)
        throws KeyStoreException, NoSuchAlgorithmException {
        Certificate[] certificateChain = keyStore.getCertificateChain(configuration.getAlias());
        if (certificateChain == null || certificateChain.length == 0) {
            logSuppressedChainToggles("no certificate chain is available");
            clearCertificateCaches(hash);
            return;
        }

        if (leafMatchesSigningKey(certificateChain[0], signingKey, configuration.getKeyResolver().name()) == LeafMatchResult.MISMATCH) {
            log.warn(
                "[generate-jwt] keystore certificate chain leaf does not match the signing key for resolver {} — certificate chain will not be embedded.",
                configuration.getKeyResolver().name()
            );
            logSuppressedChainToggles("the keystore certificate chain leaf does not match the signing key");
            clearCertificateCaches(hash);
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
            clearCertificateCaches(hash);
            return;
        }

        certChains.put(hash, certChain);

        var decodedCert = certChain.get(0).decode();
        leafCertificates.put(hash, Optional.of(computeX5t(decodedCert)));
        leafCertificatesSha256.put(hash, Optional.of(computeX5tS256(decodedCert)));
    }

    private static final Pattern TRUSTED_CERTIFICATE_BLOCK = Pattern.compile(
        "-----BEGIN TRUSTED CERTIFICATE-----(.*?)-----END TRUSTED CERTIFICATE-----",
        Pattern.DOTALL
    );

    /**
     * An OpenSSL "trusted certificate" PEM block (as produced by {@code openssl x509 -trustout}) is not just a
     * mislabeled certificate — its body is the certificate DER followed by a trailing X509_CERT_AUX ASN.1
     * structure (trust purposes, alias, key id, ...) that a plain X.509 certificate parser does not understand.
     * Rewrite each such block into a standard CERTIFICATE block containing only the leading certificate DER,
     * discarding that trailing trust-metadata, so the certificate can be extracted like any other.
     *
     * X509 CERTIFICATE-labeled blocks are intentionally not rewritten here: BouncyCastle's PEMParser
     * (used internally by X509CertChainUtils.parse) maps that label to the same certificate parser
     * as the standard CERTIFICATE label, so no metadata-stripping is needed — only TRUSTED CERTIFICATE
     * blocks carry the extra X509_CERT_AUX structure this method exists to strip.
     */
    private static String rewriteTrustedCertificateBlocksAsCertificates(String pemContent) throws CertificateException {
        Matcher matcher = TRUSTED_CERTIFICATE_BLOCK.matcher(pemContent);
        StringBuilder rewritten = new StringBuilder();
        int lastEnd = 0;
        while (matcher.find()) {
            rewritten.append(pemContent, lastEnd, matcher.start());
            rewritten.append(certificateOnlyPemBlock(matcher.group(1)));
            lastEnd = matcher.end();
        }
        rewritten.append(pemContent, lastEnd, pemContent.length());
        return rewritten.toString();
    }

    private static String certificateOnlyPemBlock(String base64Body) throws CertificateException {
        try {
            byte[] derWithTrustData = java.util.Base64.getMimeDecoder().decode(base64Body.replaceAll("\\s", ""));
            X509Certificate certificate = (X509Certificate) CertificateFactory
                .getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(derWithTrustData));
            return (
                "-----BEGIN CERTIFICATE-----\n" +
                java.util.Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8)).encodeToString(certificate.getEncoded()) +
                "\n-----END CERTIFICATE-----"
            );
        } catch (IllegalArgumentException e) {
            throw new CertificateException("Failed to decode base64 body of TRUSTED CERTIFICATE block", e);
        }
    }

    private void addLeafCertificate(String hash, String pemContent, RSAKey signingKey) throws JOSEException, NoSuchAlgorithmException {
        List<X509Certificate> certificates;
        try {
            certificates = X509CertChainUtils.parse(rewriteTrustedCertificateBlocksAsCertificates(pemContent));
        } catch (CertificateException | IOException ex) {
            log.error(
                "[generate-jwt] Failed to parse the certificate block of the key material for resolver {}.",
                configuration.getKeyResolver().name(),
                ex
            );
            clearCertificateCaches(hash);
            return;
        }

        X509Certificate signingCertificate = findSigningCertificate(certificates, signingKey);
        if (signingCertificate == null) {
            log.warn(
                "[generate-jwt] no certificate in the key material matches the signing key for resolver {} — certificate chain will not be embedded.",
                configuration.getKeyResolver().name()
            );
            if (configuration.isX509CertSha1Thumbprint()) {
                log.error(
                    "[generate-jwt] x5t toggle enabled but no certificate in the key material matches the signing key for resolver {} — thumbprint cannot be computed.",
                    configuration.getKeyResolver().name()
                );
            }
            if (configuration.isX509CertSha256Thumbprint()) {
                log.error(
                    "[generate-jwt] x5t#S256 toggle enabled but no certificate in the key material matches the signing key for resolver {} — thumbprint cannot be computed.",
                    configuration.getKeyResolver().name()
                );
            }
            if (configuration.getX509CertificateChain() == X509CertificateChain.X5C) {
                log.error(
                    "[generate-jwt] x5c certificate chain requested but no certificate in the key material matches the signing key for resolver {} — the request will be rejected.",
                    configuration.getKeyResolver().name()
                );
            }
            clearCertificateCaches(hash);
            return;
        }

        List<X509Certificate> orderedCertificates = orderCertificateChain(
            signingCertificate,
            certificates,
            configuration.getKeyResolver().name()
        );
        try {
            List<Base64> certChain = new ArrayList<>(orderedCertificates.size());
            for (X509Certificate certificate : orderedCertificates) {
                certChain.add(Base64.encode(certificate.getEncoded()));
            }
            certChains.put(hash, certChain);
            leafCertificates.put(hash, Optional.of(computeX5t(signingCertificate.getEncoded())));
            leafCertificatesSha256.put(hash, Optional.of(computeX5tS256(signingCertificate.getEncoded())));
        } catch (CertificateEncodingException ex) {
            log.error(
                "[generate-jwt] Failed to encode the certificate chain of the key material for resolver {}.",
                configuration.getKeyResolver().name(),
                ex
            );
            clearCertificateCaches(hash);
        }
    }

    private static List<X509Certificate> orderCertificateChain(
        X509Certificate signingCertificate,
        List<X509Certificate> certificates,
        String resolverName
    ) {
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
        if (!remaining.isEmpty()) {
            log.warn(
                "[generate-jwt] The x5c certificate chain for resolver {} is incomplete: {} certificate(s) could not be linked to the signing certificate and are appended unordered.",
                resolverName,
                remaining.size()
            );
        }
        ordered.addAll(remaining);
        return ordered;
    }

    private X509Certificate findSigningCertificate(List<X509Certificate> certificates, RSAKey signingKey) throws JOSEException {
        RSAPublicKey signingPublicKey = signingKey.toRSAPublicKey();
        for (X509Certificate certificate : certificates) {
            PublicKey certificatePublicKey = certificate.getPublicKey();
            if (certificatePublicKey instanceof RSAPublicKey && publicKeysMatch((RSAPublicKey) certificatePublicKey, signingPublicKey)) {
                return certificate;
            }
        }
        return null;
    }

    private enum LeafMatchResult {
        VERIFIED,
        UNVERIFIED_BYPASS,
        MISMATCH,
    }

    private static LeafMatchResult leafMatchesSigningKey(Certificate leafCertificate, PrivateKey signingKey, String resolverName) {
        if (!(leafCertificate.getPublicKey() instanceof RSAPublicKey)) {
            return LeafMatchResult.MISMATCH;
        }
        // A non-CRT RSAPrivateKey (e.g. from a PKCS11/HSM or FIPS provider) exposes no public
        // exponent, so the modulus/exponent cross-check is impossible. The leaf and the key both
        // come from the same KeyStore.PrivateKeyEntry, whose correspondence the KeyStore contract
        // already guarantees, so treat that provider-vouched pairing as a match instead of failing closed.
        if (!(signingKey instanceof RSAPrivateCrtKey)) {
            log.warn(
                "[generate-jwt] Signing key for resolver {} is a non-CRT RSA private key — the modulus/exponent cross-check between the certificate leaf and the signing key was bypassed and the KeyStore-provider-vouched leaf/key pairing was trusted instead.",
                resolverName
            );
            return LeafMatchResult.UNVERIFIED_BYPASS;
        }
        RSAPublicKey leafPublicKey = (RSAPublicKey) leafCertificate.getPublicKey();
        RSAPrivateCrtKey signingCrtKey = (RSAPrivateCrtKey) signingKey;
        boolean matches =
            leafPublicKey.getModulus().equals(signingCrtKey.getModulus()) &&
            leafPublicKey.getPublicExponent().equals(signingCrtKey.getPublicExponent());
        return matches ? LeafMatchResult.VERIFIED : LeafMatchResult.MISMATCH;
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
     * Identifies the resolved key material; this is the actual signer/certificate cache key. Must
     * include the key resolver and alias, not just content, since a single keystore file can hold
     * multiple aliases. Each field is hashed individually before joining so a field's own content
     * can't spoof the dot separator and blur the boundary between fields.
     */
    String cacheKeyMaterial() {
        String keyResolver = configuration.getKeyResolver() == null ? "" : configuration.getKeyResolver().name();
        String content = configuration.getContent() == null ? "" : configuration.getContent();
        String alias = configuration.getAlias() == null ? "" : configuration.getAlias();
        return sha1(keyResolver) + "." + sha1(content) + "." + sha1(alias);
    }

    private static Base64URL computeX5tS256(byte[] leafCertDer) throws NoSuchAlgorithmException {
        // SHA-256 is mandated here by RFC 7515 section 4.1.8 for the x5t#S256 header value, not a general-purpose hash choice.
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Base64URL.encode(digest.digest(leafCertDer));
    }

    public String sha1(String input) {
        try {
            MessageDigest msdDigest = MessageDigest.getInstance("SHA-1");
            msdDigest.update(input.getBytes(StandardCharsets.UTF_8));
            return DatatypeConverter.printHexBinary(msdDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-1 is required to compute the signer cache key but is unavailable", e);
        }
    }
}
