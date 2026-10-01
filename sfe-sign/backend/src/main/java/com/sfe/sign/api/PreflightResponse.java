package com.sfe.sign.api;

import java.util.UUID;

public record PreflightResponse(
        UUID operationId, String documentName, long sizeBytes, String sha256,
        boolean readyForConfirmation, String confirmationNotice) {
}
