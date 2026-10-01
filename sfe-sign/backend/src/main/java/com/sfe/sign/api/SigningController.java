package com.sfe.sign.api;

import com.sfe.sign.signing.SigningService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import com.sfe.sign.signing.LocalPadesSigningService;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/signatures")
public class SigningController {

    private final SigningService signingService;
    private final LocalPadesSigningService localPadesSigningService;

    public SigningController(SigningService signingService, LocalPadesSigningService localPadesSigningService) {
        this.signingService = signingService;
        this.localPadesSigningService = localPadesSigningService;
    }

    @GetMapping("/capabilities")
    public SigningCapabilities capabilities() {
        return signingService.capabilities();
    }

    @PostMapping
    @ResponseStatus(HttpStatus.ACCEPTED)
    public SignatureResponse prepare(@Valid @RequestBody SignatureRequest request) {
        return signingService.prepare(request);
    }

    @PostMapping(value = "/local/preflight", consumes = "multipart/form-data")
    public PreflightResponse preflight(@RequestPart("file") MultipartFile file) {
        return localPadesSigningService.preflight(file);
    }

    @PostMapping("/{operationId}/confirm")
    public SigningResult confirm(@PathVariable UUID operationId) {
        localPadesSigningService.sign(operationId);
        return new SigningResult(operationId, "SIGNED", "PAdES Baseline LT completed. Download and validation report are ready.");
    }

    @GetMapping("/{operationId}/download")
    public ResponseEntity<ByteArrayResource> download(@PathVariable UUID operationId) {
        byte[] document = localPadesSigningService.signed(operationId);
        if (document == null) return ResponseEntity.notFound().build();
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"signed.pdf\"")
                .contentType(org.springframework.http.MediaType.APPLICATION_PDF).body(new ByteArrayResource(document));
    }

    @GetMapping("/{operationId}/validation-report")
    public ValidationReport validationReport(@PathVariable UUID operationId) {
        ValidationReport report = localPadesSigningService.report(operationId);
        if (report == null) throw new IllegalArgumentException("Validation report is not available.");
        return report;
    }
}
