export type SignatureMode =
  | "PADES_BASELINE_LT"
  | "MULTIPLE_SIGNATURE"
  | "COUNTERSIGNATURE";

export interface SigningCapabilities {
  provider: string;
  providerConfigured: boolean;
  pkcs11LibraryAvailable: boolean;
  pkcs11ModuleReady: boolean;
  tsaConfigured: boolean;
  supportedModes: SignatureMode[];
}

export interface SignatureRequest {
  documentName: string;
  mode: SignatureMode;
}

export interface SignatureResponse {
  operationId: string;
  status: "PENDING_CONFIGURATION";
  detail: string;
}
export interface PreflightResponse {
  operationId: string;
  documentName: string;
  sizeBytes: number;
  sha256: string;
  readyForConfirmation: boolean;
  confirmationNotice: string;
}
export interface SigningResult { operationId: string; status: string; detail: string; }
export interface ValidationReport { operationId: string; status: string; signatureLevel: string; detail: string; }
interface ApiError { code: string; message: string; }

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init);
  if (!response.ok) {
    const error = await response.json().catch(() => undefined) as ApiError | undefined;
    throw new Error(error?.message ?? `Request failed with status ${response.status}`);
  }
  return response.json() as Promise<T>;
}

export const signingApi = {
  capabilities: () =>
    request<SigningCapabilities>("/api/v1/signatures/capabilities"),
  prepare: (payload: SignatureRequest) =>
    request<SignatureResponse>("/api/v1/signatures", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }),
  preflight: (file: File) => {
    const body = new FormData();
    body.append("file", file);
    return request<PreflightResponse>("/api/v1/signatures/local/preflight", { method: "POST", body });
  },
  confirm: (operationId: string) =>
    request<SigningResult>(`/api/v1/signatures/${operationId}/confirm`, { method: "POST" }),
  report: (operationId: string) =>
    request<ValidationReport>(`/api/v1/signatures/${operationId}/validation-report`)
};
