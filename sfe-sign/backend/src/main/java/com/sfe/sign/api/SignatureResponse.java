package com.sfe.sign.api;

import java.util.UUID;

public record SignatureResponse(UUID operationId, SignatureStatus status, String detail) {
}

