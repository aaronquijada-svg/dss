package com.sfe.sign.signing;

import com.sfe.sign.config.SigningProperties;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
class LocalAgentClient {
    private final SigningProperties properties;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(3)).build();

    LocalAgentClient(SigningProperties properties) {
        this.properties = properties;
    }

    boolean configured() {
        if (!StringUtils.hasText(properties.getAgentUrl()) || !StringUtils.hasText(properties.getAgentSessionSecret())) {
            return false;
        }
        try {
            URI uri = URI.create(properties.getAgentUrl());
            return "http".equalsIgnoreCase(uri.getScheme()) && "127.0.0.1".equals(uri.getHost())
                    && uri.getPort() > 0 && uri.getPath().isEmpty();
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }

    void requireReady() {
        send(HttpRequest.newBuilder(agentUri("/v1/readiness")).timeout(Duration.ofSeconds(3)).GET().build(),
                HttpResponse.BodyHandlers.discarding());
    }

    byte[] sign(LocalSigningOperation operation) {
        if (!configured()) {
            throw new IllegalStateException("The local signing agent session is not configured.");
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(agentUri("/v1/sign"))
                    .timeout(Duration.ofMinutes(5))
                    .header("X-SFE-Agent-Session", properties.getAgentSessionSecret())
                    .header("X-SFE-Document-Name", operation.documentName())
                    .header("Content-Type", "application/pdf")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(operation.source()))
                    .build();
            HttpResponse<byte[]> response = send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200 || response.body().length == 0) {
                throw new IllegalStateException("Local agent did not complete signing (HTTP " + response.statusCode() + ").");
            }
            return response.body();
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Local signing agent is unavailable or rejected the operation.", exception);
        }
    }

    private URI agentUri(String path) {
        return URI.create(properties.getAgentUrl() + path);
    }

    private <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> handler) {
        if (!configured()) throw new IllegalStateException("The local signing agent session is not configured.");
        try {
            HttpRequest.Builder authenticatedRequest = HttpRequest.newBuilder(request.uri())
                    .timeout(request.timeout().orElse(Duration.ofSeconds(5)));
            request.headers().map().forEach((name, values) ->
                    values.forEach(value -> authenticatedRequest.header(name, value)));
            authenticatedRequest.header("X-SFE-Agent-Session", properties.getAgentSessionSecret());
            authenticatedRequest.method(request.method(), request.bodyPublisher().orElse(HttpRequest.BodyPublishers.noBody()));
            HttpResponse<T> response = httpClient.send(authenticatedRequest.build(), handler);
            if (response.statusCode() != 200) {
                throw new IllegalStateException("Local signing agent is unavailable or rejected the session.");
            }
            return response;
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Local agent request was interrupted.", exception);
        } catch (java.net.http.HttpTimeoutException exception) {
            throw new IllegalStateException("Local signing agent readiness timed out after 3 seconds.", exception);
        } catch (java.net.ConnectException exception) {
            throw new IllegalStateException("Cannot connect to the configured local signing agent.", exception);
        } catch (IllegalStateException exception) {
            throw exception;
        } catch (Exception exception) {
            throw new IllegalStateException("Local signing agent is unavailable or rejected the operation.", exception);
        }
    }
}
