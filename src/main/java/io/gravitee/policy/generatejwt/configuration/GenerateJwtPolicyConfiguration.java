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

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class GenerateJwtPolicyConfiguration implements PolicyConfiguration {

    private Signature signature = Signature.RSA_RS256;

    private String kid;

    private List<String> audiences;

    private long expiresIn = 30;

    private TimeUnit expiresInUnit = TimeUnit.SECONDS;

    private String id;

    private String issuer = "urn://gravitee-api-gw";

    private String subject;

    private String content;

    private List<Claim> customClaims;

    public Signature getSignature() {
        return signature;
    }

    public void setSignature(Signature signature) {
        this.signature = signature;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public List<String> getAudiences() {
        return audiences;
    }

    public void setAudiences(List<String> audiences) {
        this.audiences = audiences;
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(long expiresIn) {
        this.expiresIn = expiresIn;
    }

    public TimeUnit getExpiresInUnit() {
        return expiresInUnit;
    }

    public void setExpiresInUnit(TimeUnit expiresInUnit) {
        this.expiresInUnit = expiresInUnit;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getContent() {
        return content;
    }

    public void setContent(String content) {
        this.content = content;
    }

    public List<Claim> getCustomClaims() {
        return customClaims;
    }

    public void setCustomClaims(List<Claim> customClaims) {
        this.customClaims = customClaims;
    }
}
