/*
 * Copyright 2002-2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.example.sp.config;

import com.example.sp.component.DelegateRelyingPartyRegistrationResolver;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.metadata.OpenSamlMetadataResolver;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.Saml2AuthenticationTokenConverter;
import org.springframework.security.saml2.provider.service.web.Saml2MetadataFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import static com.example.sp.util.OpenSAMLUtils.x509Certificate;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    public static final String DEFAULT_REGISTRATION_ID = "single";

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                // Spring Security should completely ignore URLs starting with /resources/
                .requestMatchers("/sp/consumer")
                .requestMatchers("/actuator/**");
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http, RelyingPartyRegistrationResolver delegateRelyingPartyRegistrationResolver) throws Exception {
        Saml2MetadataFilter metadataFilter = new Saml2MetadataFilter(delegateRelyingPartyRegistrationResolver,
                new OpenSamlMetadataResolver());
        // @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/error").permitAll()
				.anyRequest().authenticated()
			)
			.saml2Login(Customizer.withDefaults())
			.saml2Logout(Customizer.withDefaults())
			.addFilterBefore(metadataFilter, Saml2WebSsoAuthenticationFilter.class);
		// @formatter:on
        return http.build();
    }

    @Bean
    RelyingPartyRegistrationResolver delegateRelyingPartyRegistrationResolver(
            RelyingPartyRegistrationRepository registrations) {
        DefaultRelyingPartyRegistrationResolver defaultResolver =
                new DefaultRelyingPartyRegistrationResolver(registrations);
        DelegateRelyingPartyRegistrationResolver resolver = new DelegateRelyingPartyRegistrationResolver(defaultResolver);
        resolver.setIgnoreRegistrationId(true);
        return resolver;
    }

    @Bean
    Saml2AuthenticationTokenConverter authentication(RelyingPartyRegistrationResolver registrations) {
        return new Saml2AuthenticationTokenConverter(registrations);
    }

    @Bean
    @Profile("local")
    RelyingPartyRegistrationRepository singleRepository(
            @Value("classpath:credentials/rp-private.key") RSAPrivateKey rpKey,
            @Value("classpath:credentials/rp-certificate.crt") File rpFile,
            @Value("classpath:credentials/idp-certificate.crt") File idpFile) {
        X509Certificate rpCert = x509Certificate(rpFile);
        Saml2X509Credential signing = Saml2X509Credential.signing(rpKey, rpCert);
        Saml2X509Credential decryption = Saml2X509Credential.decryption(rpKey, rpCert);
        X509Certificate idpCert = x509Certificate(idpFile);
        Saml2X509Credential encryption = Saml2X509Credential.encryption(idpCert);
        Saml2X509Credential verification = Saml2X509Credential.verification(idpCert);

        RelyingPartyRegistration registration = RelyingPartyRegistration
                .withRegistrationId(DEFAULT_REGISTRATION_ID)
                .entityId("")
                .decryptionX509Credentials(c -> c.add(decryption))
                .assertionConsumerServiceLocation("/saml/SSO")
                .singleLogoutServiceLocation("/saml/logout")
                .singleLogoutServiceResponseLocation("/saml/SingleLogout")
                .signingX509Credentials(c -> c.add(signing))
                .assertingPartyDetails(party -> party
                        .entityId("https://idp.example.com/issuer")
                        .singleSignOnServiceLocation("https://idp.example.com/SSO.saml2")
                        .wantAuthnRequestsSigned(true)
                        .encryptionX509Credentials(c -> c.add(encryption))
                        .verificationX509Credentials(c -> c.add(verification))
                )
                .build();
        return new InMemoryRelyingPartyRegistrationRepository(registration);
    }

}
