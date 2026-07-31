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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import io.gravitee.policy.generatejwt.configuration.KeyResolver;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;

final class X5cTestSupport {

    static final String HEADER_ALG = "alg";
    static final String HEADER_X5C = "x5c";
    static final String PEM_WITH_CERT = "/priv-with-cert.pem";
    static final String PEM_NO_CERT = "/priv.pem";
    static final String PEM_FILE_SUFFIX = ".pem";
    static final String X509_CERTIFICATE_TYPE = "X.509";
    static final String X509_CERTIFICATE_CHAIN_NONE = "NONE";
    static final String X509_CERTIFICATE_CHAIN_X5C = "X5C";
    static final String RESOLVER_JKS = "JKS";
    static final String RESOLVER_PKCS12 = "PKCS12";
    static final String RESOLVER_PEM = "PEM";
    static final String RESOLVER_INLINE = "INLINE";

    private X5cTestSupport() {}

    static Map<String, Object> decodeHeader(String jwt) throws Exception {
        return JSONObjectUtils.parse(new String(Base64URL.from(jwt.split("\\.")[0]).decode(), StandardCharsets.UTF_8));
    }

    static GenerateJwtPolicyConfiguration rsaConfiguration(
        KeyResolver keyResolver,
        String content,
        String x509CertificateChain,
        boolean x509CertSha1Thumbprint,
        boolean x509CertSha256Thumbprint
    ) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode config = mapper.createObjectNode();
        config.put("signature", "RSA_RS256");
        config.put("keyResolver", keyResolver.name());
        config.put("content", content);
        config.put("x509CertificateChain", x509CertificateChain);
        config.put("x509CertSha1Thumbprint", x509CertSha1Thumbprint);
        config.put("x509CertSha256Thumbprint", x509CertSha256Thumbprint);
        return mapper.treeToValue(config, GenerateJwtPolicyConfiguration.class);
    }

    static String fixtureText(String resource) throws Exception {
        return Files.readString(new File(GenerateJwtPolicy.class.getResource(resource).toURI()).toPath());
    }
}
