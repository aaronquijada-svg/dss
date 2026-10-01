package com.sfe.sign.agent;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.signature.PAdESService;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.Pkcs11SignatureToken;
import java.awt.GraphicsEnvironment;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore.PasswordProtection;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import javax.swing.JPasswordField;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public final class LocalSigningAgent {
    private static final String SESSION_HEADER = "X-SFE-Agent-Session";
    private final AgentConfiguration configuration;
    private final String sessionSecret;

    private LocalSigningAgent(AgentConfiguration configuration, String sessionSecret) {
        this.configuration = configuration;
        this.sessionSecret = sessionSecret;
    }

    public static void main(String[] args) throws Exception {
        AgentConfiguration configuration = AgentConfiguration.fromEnvironment();
        if (GraphicsEnvironment.isHeadless()) {
            throw new IllegalStateException("The local signing agent requires a desktop session for the hidden PIN dialog.");
        }
        byte[] secretBytes = new byte[32];
        new SecureRandom().nextBytes(secretBytes);
        String secret = Base64.getUrlEncoder().withoutPadding().encodeToString(secretBytes);
        Arrays.fill(secretBytes, (byte) 0);
        LocalSigningAgent agent = new LocalSigningAgent(configuration, secret);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/readiness", agent::readiness);
        server.createContext("/v1/sign", agent::sign);
        server.setExecutor(Executors.newSingleThreadExecutor());
        server.start();
        System.out.printf("SFE local agent listening only on http://127.0.0.1:%d%n", server.getAddress().getPort());
        System.out.printf("$env:SFE_SIGN_AGENT_URL='http://127.0.0.1:%d'%n", server.getAddress().getPort());
        System.out.printf("$env:SFE_SIGN_AGENT_SESSION_SECRET='%s'%n", secret);
        System.out.println("Keep this agent window open. The secret is ephemeral and never contains a PIN.");
    }

    private void readiness(HttpExchange exchange) throws IOException {
        if (!authorized(exchange)) return;
        write(exchange, 200, "application/json", "{\"ready\":true}".getBytes(StandardCharsets.UTF_8));
    }

    private void sign(HttpExchange exchange) throws IOException {
        if (!authorized(exchange)) return;
        if (!"POST".equals(exchange.getRequestMethod())) {
            write(exchange, 405, "text/plain", "Method not allowed".getBytes(StandardCharsets.UTF_8));
            return;
        }
        byte[] sourceBytes = exchange.getRequestBody().readAllBytes();
        try {
            byte[] signed = signWithExplicitDesktopApproval(sourceBytes, exchange.getRequestHeaders().getFirst("X-SFE-Document-Name"));
            write(exchange, 200, "application/pdf", signed);
        } catch (UserCancelledException exception) {
            write(exchange, 409, "text/plain", "Local user cancelled PIN confirmation; no signing occurred.".getBytes(StandardCharsets.UTF_8));
        } catch (Exception exception) {
            write(exchange, 422, "text/plain", "Local agent could not complete PAdES Baseline LT; no signed PDF is available."
                    .getBytes(StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(sourceBytes, (byte) 0);
        }
    }

    private byte[] signWithExplicitDesktopApproval(byte[] sourceBytes, String fileName) throws Exception {
        char[] pin = requestPinWithApproval();
        try {
            try (Pkcs11SignatureToken token = new Pkcs11SignatureToken(
                    configuration.pkcs11LibraryPath(), new PasswordProtection(pin), configuration.pkcs11Slot())) {
                List<DSSPrivateKeyEntry> keys = token.getKeys();
                if (keys.isEmpty()) throw new IllegalStateException("No signing key is available.");
                DSSPrivateKeyEntry key = keys.get(0);
                DSSDocument source = new InMemoryDocument(sourceBytes, safeName(fileName));
                CommonCertificateVerifier verifier = new CommonCertificateVerifier();
                verifier.setCrlSource(new OnlineCRLSource());
                verifier.setOcspSource(new OnlineOCSPSource());
                PAdESService service = new PAdESService(verifier);
                service.setTspSource(new OnlineTSPSource(configuration.tsaUrl()));
                PAdESSignatureParameters parameters = new PAdESSignatureParameters();
                parameters.setSignatureLevel(SignatureLevel.PAdES_BASELINE_LT);
                parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
                parameters.setSigningCertificate(key.getCertificate());
                parameters.setCertificateChain(key.getCertificateChain());
                ToBeSigned data = service.getDataToSign(source, parameters);
                SignatureValue value = token.sign(data, DigestAlgorithm.SHA256, key);
                DSSDocument signed = service.signDocument(source, parameters, value);
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                signed.writeTo(output);
                if (output.size() == 0) throw new IllegalStateException("Empty signed PDF.");
                return output.toByteArray();
            }
        } finally {
            Arrays.fill(pin, '\0');
        }
    }

    private char[] requestPinWithApproval() throws Exception {
        final char[][] result = new char[1][];
        SwingUtilities.invokeAndWait(() -> {
            JPasswordField password = new JPasswordField();
            Object[] message = {
                    "A local web request asks this agent to create a PAdES Baseline LT signature.",
                    "Review the request and enter the SafeSign PIN to approve. The PIN stays in this agent only.",
                    password
            };
            int choice = JOptionPane.showConfirmDialog(null, message, "SFE-Sign local approval",
                    JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            char[] enteredPin = password.getPassword();
            if (choice == JOptionPane.OK_OPTION && enteredPin.length > 0) {
                result[0] = enteredPin;
            } else {
                Arrays.fill(enteredPin, '\0');
            }
            password.setText("");
        });
        if (result[0] == null) throw new UserCancelledException();
        return result[0];
    }

    private boolean authorized(HttpExchange exchange) throws IOException {
        String candidate = exchange.getRequestHeaders().getFirst(SESSION_HEADER);
        if (!constantTimeEquals(sessionSecret, candidate)) {
            write(exchange, 401, "text/plain", "Unauthorized local agent session".getBytes(StandardCharsets.UTF_8));
            return false;
        }
        return true;
    }

    private static boolean constantTimeEquals(String expected, String candidate) {
        if (candidate == null) return false;
        return java.security.MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8), candidate.getBytes(StandardCharsets.UTF_8));
    }

    private static String safeName(String value) {
        return value != null && value.matches("[A-Za-z0-9._-]+\\.pdf") ? value : "document.pdf";
    }

    private static void write(HttpExchange exchange, int status, String type, byte[] content) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", type);
        exchange.sendResponseHeaders(status, content.length);
        exchange.getResponseBody().write(content);
        exchange.close();
    }

    private record AgentConfiguration(String pkcs11LibraryPath, String tsaUrl, int pkcs11Slot) {
        static AgentConfiguration fromEnvironment() {
            Map<String, String> environment = System.getenv();
            String library = environment.get("SFE_SIGN_AGENT_PKCS11_LIBRARY_PATH");
            String tsa = environment.get("SFE_SIGN_AGENT_TSA_URL");
            if (library == null || library.isBlank() || !validTsaUri(tsa)) {
                throw new IllegalStateException("Set SFE_SIGN_AGENT_PKCS11_LIBRARY_PATH and SFE_SIGN_AGENT_TSA_URL.");
            }

            return new AgentConfiguration(library, tsa,
                    Integer.parseInt(environment.getOrDefault("SFE_SIGN_AGENT_PKCS11_SLOT", "0")));
        }

        private static boolean validTsaUri(String value) {
            try {
                URI uri = URI.create(value);
                return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                        && uri.getHost() != null && uri.getRawUserInfo() == null && uri.getRawFragment() == null;
            } catch (IllegalArgumentException exception) {
                return false;
            }
        }
    }

    private static final class UserCancelledException extends Exception {
    }
}
