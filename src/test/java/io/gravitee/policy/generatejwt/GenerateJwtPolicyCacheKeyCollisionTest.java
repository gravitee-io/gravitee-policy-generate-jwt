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

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.gravitee.policy.generatejwt.configuration.GenerateJwtPolicyConfiguration;
import org.junit.jupiter.api.DisplayNameGeneration;
import org.junit.jupiter.api.DisplayNameGenerator;
import org.junit.jupiter.api.Test;

@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class GenerateJwtPolicyCacheKeyCollisionTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void shouldProduceDistinctCacheKeys_whenDelimiterCharacterShiftsContentAliasBoundary() throws Exception {
        GenerateJwtPolicy policyA = new GenerateJwtPolicy(jksConfig("a.b", "c"));
        GenerateJwtPolicy policyB = new GenerateJwtPolicy(jksConfig("a", "b.c"));

        String cacheKeyA = policyA.cacheKeyMaterial();
        String cacheKeyB = policyB.cacheKeyMaterial();

        assertThat(cacheKeyA)
            .as("two distinct (content, alias) pairs must not collide on the signer/certificate cache key")
            .isNotEqualTo(cacheKeyB);
    }

    private GenerateJwtPolicyConfiguration jksConfig(String content, String alias) throws Exception {
        String json = mapper.writeValueAsString(
            mapper.createObjectNode().put("keyResolver", "JKS").put("signature", "RSA_RS256").put("content", content).put("alias", alias)
        );
        return mapper.readValue(json, GenerateJwtPolicyConfiguration.class);
    }
}
