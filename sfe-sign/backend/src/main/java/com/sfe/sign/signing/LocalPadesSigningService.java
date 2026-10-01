package com.sfe.sign.signing;

import com.sfe.sign.api.PreflightResponse;
import com.sfe.sign.api.ValidationReport;
import com.sfe.sign.config.SigningProperties;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.multipart.MultipartFile;

@Service
public class LocalPadesSigningService {
    private static final int MAX_SIZE_BYTES = 20 * 1024 * 1024;
    private final SigningProperties properties;
    private final LocalSigningStore store;
    private final LocalAgentClient localAgentClient;

    public LocalPadesSigningService(
            SigningProperties properties, LocalSigningStore store, LocalAgentClient localAgentClient) {
        this.properties = properties;
        this.store = store;
        this.localAgentClient = localAgentClient;
    }

    public PreflightResponse preflight(MultipartFile file) {
        requireSafeSignLtReadiness();
        try {
            byte[] content = file.getBytes();
            validatePdf(file, content);
            localAgentClient.requireReady();
            UUID id = UUID.randomUUID();
            String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
            store.add(new LocalSigningOperation(id, safeFileName(file.getOriginalFilename()), content, digest));
            return new PreflightResponse(id, safeFileName(file.getOriginalFilename()), content.length, digest, true,
                    "Confirming asks the separate local signing agent for desktop approval and a hidden PIN.");
        } catch (Exception exception) {
            throw new IllegalArgumentException("PDF preflight failed: " + exception.getMessage(), exception);
        }
    }

    public void sign(UUID operationId) {
        requireSafeSignLtReadiness();
        try {
            LocalSigningOperation operation = store.take(operationId);
            if (operation == null) throw new IllegalArgumentException("Unknown or expired signing operation.");
            byte[] result = localAgentClient.sign(operation);
            store.complete(operationId, result, new ValidationReport(operationId, "COMPLETED", "PAdES_BASELINE_LT",
                    "The local agent completed the requested LT signing flow. Download is available."));
        } catch (Exception exception) {
            throw new IllegalStateException("PAdES Baseline LT signing failed; no signed PDF is available: "
                    + exception.getMessage(), exception);
        }
    }

    public byte[] signed(UUID id) { return store.signed(id); }
    public ValidationReport report(UUID id) { return store.report(id); }

    private void requireSafeSignLtReadiness() {
        if (!localAgentClient.configured()) {
            throw new IllegalStateException("A configured local signing agent session is required for PAdES Baseline LT.");
        }
    }
    private void validatePdf(MultipartFile file, byte[] content) {
        if (file.isEmpty() || content.length > MAX_SIZE_BYTES) throw new IllegalArgumentException("PDF must be between 1 byte and 20 MB.");
        if (!"application/pdf".equalsIgnoreCase(file.getContentType())) throw new IllegalArgumentException("Content type must be application/pdf.");
        if (content.length < 5 || !"%PDF-".equals(new String(content, 0, 5, StandardCharsets.US_ASCII))) {
            throw new IllegalArgumentException("File content does not have a PDF header.");
        }
    }
    private String safeFileName(String name) {
        if (!StringUtils.hasText(name) || !name.toLowerCase().endsWith(".pdf")) throw new IllegalArgumentException("A .pdf file name is required.");
        return name.replaceAll("[^A-Za-z0-9._-]", "_");
    }
}
