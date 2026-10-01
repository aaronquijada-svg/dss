package com.sfe.sign.signing;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.security.ProviderException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
class SunPkcs11ReadinessProbe implements Pkcs11ReadinessProbe {

    @Override
    public Pkcs11Readiness inspect(String libraryPath) {
        if (!StringUtils.hasText(libraryPath)) {
            return Pkcs11Readiness.unavailable();
        }

        Path library;
        try {
            library = Path.of(libraryPath).toAbsolutePath().normalize();
        } catch (java.nio.file.InvalidPathException exception) {
            return Pkcs11Readiness.unavailable();
        }

        if (!Files.isRegularFile(library)) {
            return Pkcs11Readiness.unavailable();
        }

        Path configuration = null;
        try {
            configuration = Files.createTempFile("sfe-sign-safesign-", ".cfg");
            Files.writeString(configuration, configurationFor(library), StandardCharsets.UTF_8);

            Provider sunPkcs11 = Security.getProvider("SunPKCS11");
            if (sunPkcs11 == null) {
                return new Pkcs11Readiness(true, false);
            }

            sunPkcs11.configure(configuration.toString());
            return new Pkcs11Readiness(true, true);
        } catch (IOException | ProviderException | IllegalArgumentException | SecurityException exception) {
            return new Pkcs11Readiness(true, false);
        } finally {
            if (configuration != null) {
                configuration.toFile().delete();
            }
        }
    }

    private String configurationFor(Path library) {
        return "name = SafeSignReadiness%n"
                .formatted()
                + "library = %s%n".formatted(library);
    }
}

