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

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.policy.generatejwt.alg.Signature;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.net.URL;
import java.util.concurrent.TimeUnit;

public class GenerateJwtPolicyConfigurationTest {

    @Test
    public void shouldGetDefaultValues() throws IOException {
        GenerateJwtPolicyConfiguration configuration =
                load("/io/gravitee/policy/generatejwt/configuration/generatejwt01.json", GenerateJwtPolicyConfiguration.class);

        Assert.assertNotNull(configuration);

        Assert.assertEquals(Signature.RSA_RS256, configuration.getSignature());
        Assert.assertEquals(30, configuration.getExpiresIn());
        Assert.assertEquals(TimeUnit.SECONDS, configuration.getExpiresInUnit());
        Assert.assertEquals("urn://gravitee-api-gw", configuration.getIssuer());
        Assert.assertNull(configuration.getCustomClaims());
    }

    @Test
    public void shouldGetDefaultValues_withIssuer() throws IOException {
        GenerateJwtPolicyConfiguration configuration =
                load("/io/gravitee/policy/generatejwt/configuration/generatejwt02.json", GenerateJwtPolicyConfiguration.class);

        Assert.assertNotNull(configuration);

        Assert.assertEquals(Signature.RSA_RS256, configuration.getSignature());
        Assert.assertEquals(30, configuration.getExpiresIn());
        Assert.assertEquals(TimeUnit.SECONDS, configuration.getExpiresInUnit());
        Assert.assertEquals("my-custom-issuer", configuration.getIssuer());
        Assert.assertNull(configuration.getCustomClaims());
    }

    private <T> T load(String resource, Class<T> type) throws IOException {
        URL jsonFile = this.getClass().getResource(resource);
        return new ObjectMapper().readValue(jsonFile, type);
    }
}
