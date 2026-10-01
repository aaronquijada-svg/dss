package com.sfe.sign;

import com.sfe.sign.config.SigningProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(SigningProperties.class)
public class SfeSignApplication {

    public static void main(String[] args) {
        SpringApplication.run(SfeSignApplication.class, args);
    }
}

