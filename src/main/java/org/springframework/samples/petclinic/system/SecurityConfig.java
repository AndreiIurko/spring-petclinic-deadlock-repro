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

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Security configuration for the Spring PetClinic application.
 * Configures Basic HTTP Authentication with in-memory users and role-based access control.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                // Allow access to static resources and error pages without authentication
                .requestMatchers(AntPathRequestMatcher.antMatcher(\"/resources/**\")).permitAll()
                .requestMatchers(AntPathRequestMatcher.antMatcher(\"/error\")).permitAll()
                // Secure all POST, PUT, DELETE endpoints for ADMIN role
                .requestMatchers(AntPathRequestMatcher.antMatcher(\"POST\", \"/**\")).hasRole(\"ADMIN\")
                .requestMatchers(AntPathRequestMatcher.antMatcher(\"PUT\", \"/**\")).hasRole(\"ADMIN\")
                .requestMatchers(AntPathRequestMatcher.antMatcher(\"DELETE\", \"/**\")).hasRole(\"ADMIN\")
                // All other endpoints require USER role
                .requestMatchers(AntPathRequestMatcher.antMatcher(\"/**\")).hasRole(\"USER\")
            )
            .httpBasic(httpBasic -> {})
            .csrf(csrf -> csrf.disable()); // Disabling CSRF for simplicity in this example

        return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails user = User.builder()
            .username(\"user\")
            .password(passwordEncoder().encode(\"user\"))
            .roles(\"USER\")
            .build();

        UserDetails admin = User.builder()
            .username(\"admin\")
            .password(passwordEncoder().encode(\"admin\"))
            .roles(\"USER\", \"ADMIN\") // Admin also has USER role to access GET endpoints
            .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
