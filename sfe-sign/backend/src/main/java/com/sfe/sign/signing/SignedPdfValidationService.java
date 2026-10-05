package com.sfe.sign.signing;

import com.sfe.sign.api.ValidationReport;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.SignedDocumentValidator;
import eu.europa.esig.dss.validation.reports.Reports;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
class SignedPdfValidationService {

    ValidationReport validate(UUID operationId, byte[] signedPdf) {
        SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(new InMemoryDocument(signedPdf));
        validator.setCertificateVerifier(new CommonCertificateVerifier());
        Reports reports = validator.validateDocument();
        String signatureId = reports.getSimpleReport().getFirstSignatureId();
        SignatureLevel level = reports.getDiagnosticData().getSignatureFormat(signatureId);
        if (level != SignatureLevel.PAdES_BASELINE_LT) {
            throw new IllegalStateException("DSS validation did not confirm PAdES Baseline LT; no signed PDF is available.");
        }
        return new ValidationReport(
                operationId,
                reports.getSimpleReport().getIndication(signatureId).name(),
                level.name(),
                "DSS validation report generated for the signed PDF.");
    }
}
