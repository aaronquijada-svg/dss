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
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.Path;
import java.security.KeyStore.PasswordProtection;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.swing.JPasswordField;
import javax.swing.JOptionPane;
import javax.swing.SwingUtilities;

public final class LocalSigningAgent {
    private static final String SESSION_HEADER = "X-SFE-Agent-Session";
    private static final ThreadLocal<String> CURRENT_STAGE = new ThreadLocal<>();
    private static final Logger LOGGER = Logger.getLogger(LocalSigningAgent.class.getName());
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
            status("waiting for local approval");
            byte[] signed = signWithExplicitDesktopApproval(sourceBytes, exchange.getRequestHeaders().getFirst("X-SFE-Document-Name"));
            write(exchange, 200, "application/pdf", signed);
        } catch (UserCancelledException exception) {
            writeError(exchange, 409, "USER_CANCELLED", currentStage());
        } catch (AgentOperationException exception) {
            writeError(exchange, 422, exception.code(), currentStage());
        } catch (Exception exception) {
            LOGGER.log(Level.WARNING, "Local signing operation failed during " + currentStage(), exception);
            writeError(exchange, 422, "AGENT_OPERATION_FAILED", currentStage());
        } finally {
            Arrays.fill(sourceBytes, (byte) 0);
            CURRENT_STAGE.remove();
        }
    }

    private byte[] signWithExplicitDesktopApproval(byte[] sourceBytes, String fileName) throws Exception {
        char[] pin = requestPinWithApproval();
        try {
            status("opening SafeSign PKCS#11");
            try (Pkcs11SignatureToken token = createPkcs11Token(pin)) {
                List<DSSPrivateKeyEntry> keys;
                try {
                    keys = token.getKeys();
                } catch (Exception | LinkageError exception) {
                    throw pkcs11Failure(exception);
                }
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
                status("creating the PKCS#11 signature");
                SignatureValue value = token.sign(data, DigestAlgorithm.SHA256, key);
                status("requesting TSA and revocation data for PAdES LT");
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

    private Pkcs11SignatureToken createPkcs11Token(char[] pin) throws AgentOperationException {
        try {
            return new Pkcs11SignatureToken(configuration.pkcs11LibraryPath(), new PasswordProtection(pin),
                    configuration.pkcs11SlotId(), configuration.pkcs11ExtraConfig());
        } catch (Exception | LinkageError exception) {
            throw pkcs11Failure(exception);
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

    private void writeError(HttpExchange exchange, int status, String code, String stage) throws IOException {
        exchange.getResponseHeaders().set("X-SFE-Agent-Stage", stage);
        exchange.getResponseHeaders().set("X-SFE-Agent-Error-Code", code);
        write(exchange, status, "application/json",
                ("{\"code\":\"" + code + "\",\"stage\":\"" + stage + "\"}").getBytes(StandardCharsets.UTF_8));
    }

    private AgentOperationException pkcs11Failure(Throwable exception) {
        LOGGER.log(Level.WARNING, "SafeSign PKCS#11 initialization failed. "
                + "Review this local-agent console for middleware diagnostics.", exception);
        String diagnostic = String.valueOf(exception.getMessage()).toLowerCase(java.util.Locale.ROOT);
        if (exception instanceof UnsatisfiedLinkError || diagnostic.contains("loadlibrary")
                || diagnostic.contains("can't load") || diagnostic.contains("cannot load")) {
            return new AgentOperationException("PKCS11_LIBRARY_UNAVAILABLE");
        }
        if (diagnostic.contains("slot") || diagnostic.contains("token not present")
                || diagnostic.contains("token_not_present")) {
            return new AgentOperationException("PKCS11_SLOT_UNAVAILABLE");
        }
        return new AgentOperationException("PKCS11_PROVIDER_INITIALIZATION_FAILED");
    }

    private static void status(String stage) {
        CURRENT_STAGE.set(stage);
        System.out.println("SFE agent stage: " + stage);
    }

    private static String currentStage() {
        String stage = CURRENT_STAGE.get();
        return stage == null ? "an unspecified local-agent stage" : stage;
    }

    private record AgentConfiguration(String pkcs11LibraryPath, String tsaUrl, int pkcs11SlotId,
                                      Integer pkcs11SlotListIndex) {
        static AgentConfiguration fromEnvironment() {
            Map<String, String> environment = System.getenv();
            String library = environment.get("SFE_SIGN_AGENT_PKCS11_LIBRARY_PATH");
            String tsa = environment.get("SFE_SIGN_AGENT_TSA_URL");
            if (library == null || library.isBlank() || !validTsaUri(tsa)) {
                throw new IllegalStateException("Set SFE_SIGN_AGENT_PKCS11_LIBRARY_PATH and SFE_SIGN_AGENT_TSA_URL.");
            }
            try {
                if (!Files.isRegularFile(Path.of(library))) {
                    throw new IllegalStateException("The configured SafeSign PKCS#11 library is not a readable file.");
                }
            } catch (InvalidPathException exception) {
                throw new IllegalStateException("The configured SafeSign PKCS#11 library path is invalid.", exception);
            }

            Integer slotId = nonNegativeEnvironmentInteger(environment, "SFE_SIGN_AGENT_PKCS11_SLOT");
            Integer slotListIndex = nonNegativeEnvironmentInteger(environment, "SFE_SIGN_AGENT_PKCS11_SLOT_LIST_INDEX");
            if (slotId != null && slotListIndex != null) {
                throw new IllegalStateException("Set only one of SFE_SIGN_AGENT_PKCS11_SLOT or "
                        + "SFE_SIGN_AGENT_PKCS11_SLOT_LIST_INDEX.");
            }

            return new AgentConfiguration(library, tsa, slotId == null ? -1 : slotId, slotListIndex);
        }

        String pkcs11ExtraConfig() {
            return pkcs11SlotListIndex == null ? null : "slotListIndex = " + pkcs11SlotListIndex;
        }

        private static Integer nonNegativeEnvironmentInteger(Map<String, String> environment, String name) {
            String value = environment.get(name);
            if (value == null || value.isBlank()) return null;
            try {
                int parsed = Integer.parseInt(value);
                if (parsed < 0) throw new NumberFormatException();
                return parsed;
            } catch (NumberFormatException exception) {
                throw new IllegalStateException(name + " must be a non-negative integer.", exception);
            }
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

    private static final class AgentOperationException extends Exception {
        private final String code;

        private AgentOperationException(String code) {
            this.code = code;
        }

        private String code() {
            return code;
        }
    }
}
