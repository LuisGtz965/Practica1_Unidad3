package com.example.securebackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class SecureBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureBackendApplication.class, args);
    }
}
