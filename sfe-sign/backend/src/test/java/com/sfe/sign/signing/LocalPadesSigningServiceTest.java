package com.sfe.sign.signing;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sfe.sign.config.SigningProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockMultipartFile;

class LocalPadesSigningServiceTest {

    private LocalPadesSigningService service() {
        SigningProperties properties = new SigningProperties();
        properties.setAgentUrl("http://127.0.0.1:12345");
        properties.setAgentSessionSecret("test-session-secret");
        return new LocalPadesSigningService(
                properties, new LocalSigningStore(), new LocalAgentClient(properties), null);
    }

    @Test
    void rejectsAFileWithoutPdfMagicBytes() {
        MockMultipartFile file = new MockMultipartFile(
                "file", "test.pdf", "application/pdf", "not a pdf".getBytes());

        assertThatThrownBy(() -> service().preflight(file))
                .hasMessageContaining("PDF preflight failed")
                .hasMessageContaining("PDF header");
    }

    @Test
    void rejectsAFileWithAnUnexpectedContentType() {
        MockMultipartFile file = new MockMultipartFile(
                "file", "test.pdf", "text/plain", "%PDF-1.7".getBytes());

        assertThatThrownBy(() -> service().preflight(file))
                .hasMessageContaining("Content type");
    }

    @Test
    void requiresAnAgentSessionBeforeAcceptingAValidPdf() {
        SigningProperties properties = new SigningProperties();
        LocalPadesSigningService service = new LocalPadesSigningService(
                properties, new LocalSigningStore(), new LocalAgentClient(properties), null);
        MockMultipartFile file = new MockMultipartFile(
                "file", "test.pdf", "application/pdf", "%PDF-1.7".getBytes());

        assertThatThrownBy(() -> service.preflight(file))
                .hasMessageContaining("local signing agent session");
    }
}
