package com.example.idp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.saml2.core.OpenSamlInitializationService;

@SpringBootApplication
public class SamlIdpServerApplication {
    static {
        OpenSamlInitializationService.initialize();
    }
    public static void main(String[] args) {
        SpringApplication.run(SamlIdpServerApplication.class, args);
    }
}
