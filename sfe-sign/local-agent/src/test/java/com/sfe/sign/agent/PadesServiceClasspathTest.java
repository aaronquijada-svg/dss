package com.sfe.sign.agent;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;

import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.utils.IUtils;
import eu.europa.esig.dss.utils.Utils;
import java.util.ServiceLoader;
import org.junit.jupiter.api.Test;

class PadesServiceClasspathTest {

    @Test
    void loadsDssUtilitiesProviderBeforeInitializingPadesService() {
        assertFalse(ServiceLoader.load(IUtils.class).stream().findAny().isEmpty());
        assertDoesNotThrow(() -> {
            Utils.isStringEmpty("");
            new PAdESService(new CommonCertificateVerifier());
        });
    }
}
