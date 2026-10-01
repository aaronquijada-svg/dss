import { FormEvent, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  SignatureMode,
  SigningCapabilities,
  signingApi
} from "./api";
import "./styles.css";

const modes: Array<{ value: SignatureMode; label: string }> = [
  { value: "PADES_BASELINE_LT", label: "PAdES Baseline LT" },
  { value: "MULTIPLE_SIGNATURE", label: "Multiple signatures" },
  { value: "COUNTERSIGNATURE", label: "Countersignature" }
];

function App() {
  const [capabilities, setCapabilities] = useState<SigningCapabilities>();
  const [documentName, setDocumentName] = useState("");
  const [mode, setMode] = useState<SignatureMode>("PADES_BASELINE_LT");
  const [message, setMessage] = useState<string>();
  const [preflight, setPreflight] = useState<import("./api").PreflightResponse>();
  const [report, setReport] = useState<import("./api").ValidationReport>();

  useEffect(() => {
    signingApi.capabilities().then(setCapabilities).catch(() => {
      setMessage("The signing API is unavailable.");
    });
  }, []);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(undefined);
    try {
      const result = await signingApi.prepare({ documentName, mode });
      setMessage(result.detail);
    } catch {
      setMessage("Unable to prepare the signing operation. Use a PDF file name.");
    }
  }
  async function preflightFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = new FormData(event.currentTarget).get("file");
    if (!(file instanceof File)) return;
    try {
      setPreflight(await signingApi.preflight(file));
      setMessage(undefined);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "PDF preflight failed. Use a PDF no larger than 20 MB.");
    }
  }
  async function confirm() {
    if (!preflight) return;
    try {
      const result = await signingApi.confirm(preflight.operationId);
      setMessage(result.detail);
      setReport(await signingApi.report(preflight.operationId));
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Signing failed. No signed PDF was made available.");
    }
  }

  return (
    <main>
      <header>
        <p className="eyebrow">Digital signature workspace</p>
        <h1>SFE-Sign</h1>
        <p>Prepare secure PAdES operations without exposing signing credentials.</p>
      </header>
      <section className="card">
        <h2>Signing readiness</h2>
        <dl>
          <dt>Provider</dt><dd>{capabilities?.provider ?? "Checking…"}</dd>
          <dt>PKCS#11 configured</dt><dd>{capabilities?.providerConfigured ? "Yes" : "No"}</dd>
          <dt>PKCS#11 library available</dt><dd>{capabilities?.pkcs11LibraryAvailable ? "Yes" : "No"}</dd>
          <dt>Smartcard module ready</dt><dd>{capabilities?.pkcs11ModuleReady ? "Yes" : "No"}</dd>
          <dt>TSA URL configured (no requests)</dt><dd>{capabilities?.tsaConfigured ? "Yes" : "No"}</dd>
        </dl>
      </section>
      <section className="card">
        <h2>Local PAdES Baseline LT</h2>
        <p>Confirmation requests approval from the separate local agent. The PIN is entered only in its native hidden-password dialog, never here.</p>
        <form onSubmit={preflightFile}>
          <label>PDF file<input name="file" type="file" accept="application/pdf,.pdf" required /></label>
          <button type="submit">Run preflight</button>
        </form>
        {preflight && <div className="notice">
          <p><strong>{preflight.documentName}</strong> — {preflight.sizeBytes} bytes</p>
          <p>SHA-256: <code>{preflight.sha256}</code></p>
          <p>{preflight.confirmationNotice}</p>
          <button type="button" onClick={confirm}>Confirm and sign locally</button>
        </div>}
        {report && <p className="notice">Validation: {report.status} ({report.signatureLevel}). {report.detail}</p>}
        {preflight && report && <a href={`/api/v1/signatures/${preflight.operationId}/download`}>Download signed PDF</a>}
      </section>
      <section className="card">
        <h2>Prepare an operation</h2>
        <form onSubmit={submit}>
          <label>
            PDF document name
            <input value={documentName} onChange={(event) => setDocumentName(event.target.value)}
              placeholder="contract.pdf" required />
          </label>
          <label>
            Signature mode
            <select value={mode} onChange={(event) => setMode(event.target.value as SignatureMode)}>
              {modes.map(({ value, label }) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          <button type="submit">Prepare signing</button>
        </form>
        {message && <p className="notice" role="status">{message}</p>}
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
