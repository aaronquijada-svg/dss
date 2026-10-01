package com.sfe.sign.signing;

import java.util.UUID;

record LocalSigningOperation(UUID id, String documentName, byte[] source, String sha256) {
}
