/**
 * Typed evidence renderer.
 *
 * Renders finding.evidence as a structured layout instead of raw JSON.
 * For known finding types (cert, SSH, KMS, etc.) uses a typed layout.
 * For unknown types falls back to a clean key-value grid.
 */
import { KeyValueGrid, KeyValueItem } from "./KeyValueGrid";

export interface EvidenceRendererProps {
  findingType?: string;
  algorithm?: string;
  algorithmType?: string;
  pqcStatus?: string;
  evidence?: Record<string, any> | null;
  recommendedAlgorithm?: string;
  layer?: string;
  hndlExposure?: string;
}

export function EvidenceRenderer({
  findingType,
  algorithm,
  algorithmType,
  pqcStatus,
  evidence,
  recommendedAlgorithm,
  layer,
  hndlExposure,
}: EvidenceRendererProps) {
  const items: KeyValueItem[] = [];

  if (algorithm) items.push({ label: "Algorithm", value: algorithm, mono: true });
  if (algorithmType) items.push({ label: "Algorithm Type", value: algorithmType });
  if (pqcStatus) items.push({ label: "PQC Status", value: pqcStatus, badge: true });
  if (layer) items.push({ label: "Layer", value: layer });
  if (hndlExposure) items.push({ label: "HNDL Exposure", value: hndlExposure });

  if (evidence && typeof evidence === "object") {
    const ft = findingType ?? "";
    if (ft === "weak_signature_algorithm" || ft === "expired_certificate" || ft === "weak_pubkey") {
      if (evidence.thumbprint) items.push({ label: "Cert Thumbprint", value: String(evidence.thumbprint), mono: true });
      if (evidence.subject) items.push({ label: "Subject", value: String(evidence.subject) });
      if (evidence.issuer) items.push({ label: "Issuer", value: String(evidence.issuer) });
      if (evidence.serial_number) items.push({ label: "Serial", value: String(evidence.serial_number), mono: true });
      if (evidence.not_before) items.push({ label: "Valid From", value: String(evidence.not_before) });
      if (evidence.not_after) items.push({ label: "Valid Until", value: String(evidence.not_after) });
      if (evidence.key_size) items.push({ label: "Key Size", value: `${evidence.key_size} bit` });
      if (evidence.curve) items.push({ label: "Curve", value: String(evidence.curve) });
      if (evidence.sig_algorithm) items.push({ label: "Signature Algorithm", value: String(evidence.sig_algorithm), mono: true });
    } else if (ft.startsWith("ssh_")) {
      if (evidence.kex_algorithms) items.push({ label: "KEX Algorithms Offered", value: evidence.kex_algorithms, list: true });
      if (evidence.cipher_algorithms) items.push({ label: "Cipher Algorithms", value: evidence.cipher_algorithms, list: true });
      if (evidence.mac_algorithms) items.push({ label: "MAC Algorithms", value: evidence.mac_algorithms, list: true });
      if (evidence.server_host_key) items.push({ label: "Server Host Key", value: String(evidence.server_host_key), mono: true });
    } else if (ft.startsWith("aws_") || ft.startsWith("kms_")) {
      if (evidence.service) items.push({ label: "AWS Service", value: String(evidence.service) });
      if (evidence.resource_id) items.push({ label: "Resource ID", value: String(evidence.resource_id), mono: true });
      if (evidence.arn) items.push({ label: "ARN", value: String(evidence.arn), mono: true });
      if (evidence.region) items.push({ label: "Region", value: String(evidence.region) });
      if (evidence.key_spec) items.push({ label: "Key Spec", value: String(evidence.key_spec) });
      if (evidence.key_state) items.push({ label: "Key State", value: String(evidence.key_state) });
      if (evidence.policy_name) items.push({ label: "Policy", value: String(evidence.policy_name) });
    } else {
      for (const [k, v] of Object.entries(evidence)) {
        if (k === "description" || k === "remediation") continue;
        if (Array.isArray(v) || typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
          items.push({ label: humanize(k), value: v, list: Array.isArray(v) });
        }
      }
    }
  }

  if (recommendedAlgorithm) {
    items.push({ label: "Recommended", value: recommendedAlgorithm, mono: true, accent: "cyan" });
  }

  return <KeyValueGrid items={items} />;
}

function humanize(s: string): string {
  return s
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}
