# SFE-Sign

SFE-Sign is a standalone starter application for digital signing. It is deliberately
kept outside the DSS Maven reactor: DSS modules are not changed and this application
consumes the released **DSS 6.5** artifacts from Maven Central.

The current increment exposes a typed REST API and a React user interface. It
establishes the contracts and provider boundary for future PAdES Baseline LT,
multiple-signature, and countersignature workflows; it does not sign documents yet.

## Prerequisites

* JDK 21 (the application targets Java 17)
* Maven 3.9+
* Node.js 20+

## Run

1. Copy `backend/.env.example` to a location managed by your deployment platform,
   then set environment variables there. Do not commit that file with secrets.
2. Start the API:

   ```powershell
   cd sfe-sign\backend
   mvn spring-boot:run
   ```

3. In another terminal, start the web client:

   ```powershell
   cd sfe-sign\frontend
   npm install
   npm run dev
   ```

The API defaults to `http://localhost:18080`, avoiding the conventional `8080`
development-port collision. Set `SFE_SIGN_SERVER_PORT` to use another port and
set the matching `VITE_API_TARGET` in `frontend/.env.local`; the frontend proxies
`/api` to that target in development.

## Security boundary

`SFE_SIGN_SIGNING_PROVIDER=safesign` selects the SafeSign adapter and
`SFE_SIGN_PKCS11_LIBRARY_PATH=C:\Windows\System32\aetpkss1.dll` supplies its
native-library location. With the card inserted, the capabilities endpoint performs
a no-login availability check by initializing the JDK PKCS#11 provider with the DLL.
It never requests, accepts, logs, persists, or transmits a PIN, and it does not open
a keystore, enumerate certificates, or sign. This means certificate aliases and
subjects are intentionally not exposed, even if the token could reveal them without
login.

For local readiness checks, set only these process environment variables before
restarting the API:

```powershell
$env:SFE_SIGN_SIGNING_PROVIDER = "safesign"
$env:SFE_SIGN_PKCS11_LIBRARY_PATH = "C:\Windows\System32\aetpkss1.dll"
mvn spring-boot:run
```

`GET /api/v1/signatures/capabilities` reports `pkcs11LibraryAvailable` and
`pkcs11ModuleReady`; it does not return the DLL path, token details, or certificate
data. A production signing ceremony must provide PIN entry/session handling outside
HTTP request storage and implement the provider's signing operation.

Set `SFE_SIGN_TSA_URL` only through deployment configuration when a TSA is approved.
It must be an absolute `http` or `https` URI with a host and without embedded
credentials or a fragment. The capabilities endpoint reports only whether it is
configured; it never returns the URL. This increment does not contact the TSA,
request timestamps, send POST requests, or sign documents. No TSA endpoint is
embedded in source, examples, defaults, or configuration files.

## Local PAdES LT test

This test flow accepts a PDF up to 20 MB, validates its MIME type, `.pdf` name and
`%PDF-` header, and holds it only in backend memory until the operation completes.
The UI first shows the file name, size and SHA-256 digest. **Only its explicit
confirmation** requests a separate local agent to show its own native desktop
approval dialog. The PIN is entered into that dialog's hidden password field and is
never sent through HTTP, displayed in the web UI, logged, configured, or persisted.

Start the local agent in a desktop session (replace the TSA URL with the approved
value provided for your environment):

```powershell
cd sfe-sign\local-agent
$env:SFE_SIGN_AGENT_PKCS11_LIBRARY_PATH = "C:\Windows\System32\aetpkss1.dll"
$env:SFE_SIGN_AGENT_TSA_URL = "<approved TSA URL>"
mvn exec:java
```

The agent binds only to `127.0.0.1` on a random port and prints two PowerShell
assignments: `SFE_SIGN_AGENT_URL` and its fresh, in-memory
`SFE_SIGN_AGENT_SESSION_SECRET`. In a second terminal, paste those exact assignments
and then start the backend:

```powershell
cd sfe-sign\backend
mvn spring-boot:run
```

Start Vite, open its local URL, run **Run preflight**, then choose **Confirm and
sign locally**. The agent shows a native confirmation dialog and only then a hidden
PIN field. The agent makes TSA, OCSP, and CRL requests only after this local desktop
approval because PAdES Baseline LT requires them. A missing agent, failed session,
TSA/revocation/signing failure, or dialog cancellation returns an error and no
download is published.

Preflight makes an authenticated readiness request to the agent with a three-second
timeout. If it cannot connect, times out, or the session secret differs, the UI shows
the exact local-agent error and does not create a signing operation.

This is a single-user local proof of concept: the browser can invoke the local
confirmation endpoint and the backend process owns the terminal prompt. Do not expose
this backend on a network. A multi-user design must move token access and PIN entry
to an authenticated local signing agent using an OS-protected IPC channel, scoped
operation approvals, short-lived signed requests, and an explicit user-presence UI.
