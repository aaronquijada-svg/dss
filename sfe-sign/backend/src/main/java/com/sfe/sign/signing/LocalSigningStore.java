package com.sfe.sign.signing;

import com.sfe.sign.api.ValidationReport;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

@Component
class LocalSigningStore {
    private final Map<UUID, LocalSigningOperation> pending = new ConcurrentHashMap<>();
    private final Map<UUID, byte[]> signed = new ConcurrentHashMap<>();
    private final Map<UUID, ValidationReport> reports = new ConcurrentHashMap<>();

    void add(LocalSigningOperation operation) { pending.put(operation.id(), operation); }
    LocalSigningOperation take(UUID id) { return pending.remove(id); }
    void complete(UUID id, byte[] document, ValidationReport report) { signed.put(id, document); reports.put(id, report); }
    byte[] signed(UUID id) { return signed.get(id); }
    ValidationReport report(UUID id) { return reports.get(id); }
}
