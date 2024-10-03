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
package io.gravitee.policy.generatejwt.configuration;

import io.gravitee.policy.api.PolicyConfiguration;
import io.gravitee.policy.generatejwt.alg.Signature;
import io.gravitee.policy.generatejwt.model.Claim;
import java.util.List;
import java.util.concurrent.TimeUnit;
import lombok.Getter;
import lombok.Setter;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Setter
@Getter
public class GenerateJwtPolicyConfiguration implements PolicyConfiguration {

    private KeyResolver keyResolver = KeyResolver.INLINE;

    private Signature signature = Signature.RSA_RS256;

    private String content;

    private String alias;

    private String storepass;

    private String keypass;

    private String kid;

    private X509CertificateChain x509CertificateChain = X509CertificateChain.NONE;

    private List<String> audiences;

    private long expiresIn = 30;

    private TimeUnit expiresInUnit = TimeUnit.SECONDS;

    private String id;

    private String issuer = "urn://gravitee-api-gw";

    private String subject;

    private Boolean secretBase64Encoded = false;

    private List<Claim> customClaims;
}
