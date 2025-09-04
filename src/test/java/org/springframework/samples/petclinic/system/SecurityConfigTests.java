/*
 * Copyright 2012-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the \"License\");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an \"AS IS\" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.samples.petclinic.system;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Test class for {@link SecurityConfig}
 */
@WebMvcTest(WelcomeController.class)
@Import(SecurityConfig.class)
class SecurityConfigTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void unauthenticatedUserShouldBeUnauthorized() throws Exception {
        mockMvc.perform(get(\"/\"))
            .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser(username = \"user\", roles = \"USER\")
    void userCanAccessGetEndpoints() throws Exception {
        mockMvc.perform(get(\"/\"))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = \"user\", roles = \"USER\")
    void userCannotAccessPostEndpoints() throws Exception {
        mockMvc.perform(post(\"/owners/new\")
            .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isForbidden());
    }

    @Test
    @WithMockUser(username = \"admin\", roles = {\"USER\", \"ADMIN\"})
    void adminCanAccessPostEndpoints() throws Exception {
        mockMvc.perform(post(\"/owners/new\")
            .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(status().isOk());
    }

    @Test
    @WithMockUser(username = \"admin\", roles = {\"USER\", \"ADMIN\"})
    void adminCanAccessGetEndpoints() throws Exception {
        mockMvc.perform(get(\"/\"))
            .andExpect(status().isOk());
    }
}
