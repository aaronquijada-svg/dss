package com.sfe.sign.api;

import java.util.UUID;

public record SigningResult(UUID operationId, String status, String detail) {
}
