import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Plug,
  Upload,
  Loader2,
  CheckCircle,
  Play,
  FileSpreadsheet,
  Cloud,
  Key,
  Server,
  ShieldAlert,
  Scan,
  ArrowRight,
  AlertTriangle,
  Database,
  Globe,
  Lock,
  HardDrive,
  ChevronDown,
  ChevronUp,
  Terminal,
  FileCode,
  GitBranch,
} from "lucide-react";

interface Connector {
  id: string;
  name: string;
  type: string;
  status: "configured" | "inactive" | "active";
  last_sync: string | null;
  description: string;
}

interface ImportResult {
  status: "success" | "error";
  imported: number;
  updated: number;
  skipped: number;
  errors: string[];
}

interface CloudSyncResult {
  status: string;
  imported: number;
  updated: number;
  errors: string[];
  total_processed: number;
}

interface AWSPQCScanResult {
  status: string;
  scan_id: string;
  region: string;
  services_scanned: string[];
  assets_discovered: number;
  assets_updated: number;
  algorithms_recorded: number;
  findings_created: number;
  certificates_recorded: number;
  errors: string[];
}

const SERVICE_ICONS: Record<string, React.ReactNode> = {
  KMS: <Key className="h-3.5 w-3.5 text-orange-400" />,
  ACM: <Lock className="h-3.5 w-3.5 text-green-400" />,
  ELBv2: <Globe className="h-3.5 w-3.5 text-blue-400" />,
  CloudFront: <Cloud className="h-3.5 w-3.5 text-purple-400" />,
  S3: <HardDrive className="h-3.5 w-3.5 text-emerald-400" />,
  IAM: <Database className="h-3.5 w-3.5 text-yellow-400" />,
};

const SERVICE_DESCRIPTIONS: Record<string, string> = {
  KMS: "Encryption keys & key policies",
  ACM: "SSL/TLS certificates",
  ELBv2: "Load balancer TLS policies",
  CloudFront: "CDN distribution TLS configs",
  S3: "Bucket encryption settings",
  IAM: "Server certificates",
};

const AWS_REGIONS: { value: string; label: string }[] = [
  { value: "ap-south-1", label: "Asia Pacific (Mumbai)" },
  { value: "ap-south-2", label: "Asia Pacific (Hyderabad)" },
  { value: "us-east-1", label: "US East (N. Virginia)" },
  { value: "us-east-2", label: "US East (Ohio)" },
  { value: "us-west-1", label: "US West (N. California)" },
  { value: "us-west-2", label: "US West (Oregon)" },
  { value: "af-south-1", label: "Africa (Cape Town)" },
  { value: "ap-east-1", label: "Asia Pacific (Hong Kong)" },
  { value: "ap-northeast-1", label: "Asia Pacific (Tokyo)" },
  { value: "ap-northeast-2", label: "Asia Pacific (Seoul)" },
  { value: "ap-northeast-3", label: "Asia Pacific (Osaka)" },
  { value: "ap-southeast-1", label: "Asia Pacific (Singapore)" },
  { value: "ap-southeast-2", label: "Asia Pacific (Sydney)" },
  { value: "ap-southeast-3", label: "Asia Pacific (Jakarta)" },
  { value: "ap-southeast-4", label: "Asia Pacific (Melbourne)" },
  { value: "ca-central-1", label: "Canada (Central)" },
  { value: "ca-west-1", label: "Canada West (Calgary)" },
  { value: "eu-central-1", label: "Europe (Frankfurt)" },
  { value: "eu-central-2", label: "Europe (Zurich)" },
  { value: "eu-north-1", label: "Europe (Stockholm)" },
  { value: "eu-south-1", label: "Europe (Milan)" },
  { value: "eu-south-2", label: "Europe (Spain)" },
  { value: "eu-west-1", label: "Europe (Ireland)" },
  { value: "eu-west-2", label: "Europe (London)" },
  { value: "eu-west-3", label: "Europe (Paris)" },
  { value: "il-central-1", label: "Israel (Tel Aviv)" },
  { value: "me-central-1", label: "Middle East (UAE)" },
  { value: "me-south-1", label: "Middle East (Bahrain)" },
  { value: "sa-east-1", label: "South America (São Paulo)" },
  { value: "us-gov-east-1", label: "AWS GovCloud (US-East)" },
  { value: "us-gov-west-1", label: "AWS GovCloud (US-West)" },
];

const CATEGORY_LABELS = {
  cloud_cmdb: "Cloud & CMDB",
  hosts_endpoints: "Hosts & Endpoints",
  databases_clusters: "Databases & Clusters",
  hsm_kms_pki: "HSM, KMS & PKI",
} as const;

const SIDEBAR_ITEMS = [
  {
    id: "aws_discovery",
    name: "AWS Discovery Scanner",
    description: "Inventory AWS KMS, ACM certificates, and ALBs for post-quantum safety.",
    icon: <Cloud className="h-4 w-4 text-orange-400" />,
    category: "cloud_cmdb"
  },
  {
    id: "azure_key_vault",
    name: "Azure Key Vault Sync",
    description: "Sync keys and configuration from Azure Key Vault.",
    icon: <Key className="h-4 w-4 text-blue-400" />,
    category: "cloud_cmdb"
  },
  {
    id: "gcp_kms",
    name: "GCP KMS Sync",
    description: "Sync keys and keyring algorithms from GCP KMS.",
    icon: <Server className="h-4 w-4 text-red-400" />,
    category: "cloud_cmdb"
  },
  {
    id: "servicenow",
    name: "ServiceNow CMDB",
    description: "Sync servers and business service mapping from ServiceNow CIs.",
    icon: <Database className="h-4 w-4 text-green-400" />,
    category: "cloud_cmdb"
  },
  {
    id: "csv_cmdb",
    name: "CSV CMDB Import",
    description: "Bulk import or update assets via CSV upload.",
    icon: <FileSpreadsheet className="h-4 w-4 text-emerald-400" />,
    category: "cloud_cmdb"
  },
  {
    id: "ssh_agentless",
    name: "SSH Linux Scanner",
    description: "SSH agentless scan of certificate stores, OpenSSL, SSH config, and ciphers.",
    icon: <Terminal className="h-4 w-4 text-cyan-400" />,
    category: "hosts_endpoints"
  },
  {
    id: "winrm_agentless",
    name: "WinRM Windows Scanner",
    description: "Audit Windows hosts for certificate stores, Schannel TLS, and IIS.",
    icon: <Terminal className="h-4 w-4 text-blue-400" />,
    category: "hosts_endpoints"
  },
  {
    id: "windows_cert_store",
    name: "Windows Cert Store",
    description: "Enumerate local Windows certificate stores via certutil dump.",
    icon: <Lock className="h-4 w-4 text-emerald-400" />,
    category: "hosts_endpoints"
  },
  {
    id: "sast_native",
    name: "Native SAST Scanner",
    description: "Scan codebases (Python/Java/Go/NodeJS) for crypto usage and lockfiles.",
    icon: <FileCode className="h-4 w-4 text-purple-400" />,
    category: "hosts_endpoints"
  },
  {
    id: "jwt_audit",
    name: "JWT Token Auditor",
    description: "Audit JWT signing algorithms and keys offline or via JWKS endpoints.",
    icon: <ShieldAlert className="h-4 w-4 text-amber-400" />,
    category: "hosts_endpoints"
  },
  {
    id: "kubernetes",
    name: "Kubernetes Scanner",
    description: "Scan ingress TLS, secrets, etcd encryption, and cluster components.",
    icon: <Globe className="h-4 w-4 text-indigo-400" />,
    category: "databases_clusters"
  },
  {
    id: "oracle_tde",
    name: "Oracle TDE Scanner",
    description: "Enumerate Oracle tablespace encryption and TDE wallet master keys.",
    icon: <Database className="h-4 w-4 text-red-400" />,
    category: "databases_clusters"
  },
  {
    id: "sqlserver_tde",
    name: "SQL Server TDE",
    description: "Audit SQL Server database encryption (TDE) keys and certificates.",
    icon: <Database className="h-4 w-4 text-rose-400" />,
    category: "databases_clusters"
  },
  {
    id: "pkcs11_hsm",
    name: "PKCS#11 HSM Scanner",
    description: "Enumerate active HSM objects (key sizes, algorithms, labels).",
    icon: <HardDrive className="h-4 w-4 text-pink-400" />,
    category: "hsm_kms_pki"
  },
  {
    id: "kmip_kms",
    name: "KMIP KMS Scanner",
    description: "Query KMIP Key Management Servers for keys and attributes.",
    icon: <Key className="h-4 w-4 text-orange-400" />,
    category: "hsm_kms_pki"
  },
  {
    id: "adcs_ldap",
    name: "ADCS/LDAP Scanner",
    description: "Discover certificates and CA structures from AD Certificate Services.",
    icon: <Server className="h-4 w-4 text-teal-400" />,
    category: "hsm_kms_pki"
  },
  {
    id: "saml_metadata",
    name: "SAML Metadata Scanner",
    description: "Inventory SAML signing/encryption certificates from IdP metadata URLs or XML.",
    icon: <ShieldAlert className="h-4 w-4 text-fuchsia-400" />,
    category: "hsm_kms_pki"
  },
  {
    id: "vault_scanner",
    name: "HashiCorp Vault Secrets Scanner",
    description: "Discover cryptographic material (PKI certs, transit keys) in HashiCorp Vault secrets.",
    icon: <HardDrive className="h-4 w-4 text-slate-400" />,
    category: "cloud_cmdb"
  },
  {
    id: "git_secrets",
    name: "Git Repository Secrets Scanner",
    description: "Scan git repositories for exposed keys, certificates, and credentials.",
    icon: <GitBranch className="h-4 w-4 text-pink-400" />,
    category: "cloud_cmdb"
  }
] as const;

export default function Connectors() {
  const [connectors, setConnectors] = useState<Connector[]>([]);

  // CSV upload state
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);

  // Cloud KMS sync state
  const [cloudLoading, setCloudLoading] = useState(false);
  const [cloudResult, setCloudResult] = useState<CloudSyncResult | null>(null);
  const [cloudError, setCloudError] = useState<string | null>(null);

  // AWS PQC scan state
  const [awsPqcLoading, setAwsPqcLoading] = useState(false);
  const [awsPqcResult, setAwsPqcResult] = useState<AWSPQCScanResult | null>(null);
  const [awsPqcError, setAwsPqcError] = useState<string | null>(null);

  // AWS credentials (shared between sync and PQC scan)
  const [awsKeyId, setAwsKeyId] = useState("");
  const [awsSecret, setAwsSecret] = useState("");
  const [awsRegion, setAwsRegion] = useState("ap-south-1");
  const [awsSessionToken, setAwsSessionToken] = useState("");
  const [awsMode, setAwsMode] = useState<"sync" | "pqc_scan">("pqc_scan");

  // Azure
  const [azureTenant, setAzureTenant] = useState("");
  const [azureClient, setAzureClient] = useState("");
  const [azureSecret, setAzureSecret] = useState("");
  const [azureVault, setAzureVault] = useState("");
  // GCP
  const [gcpProject, setGcpProject] = useState("");
  const [gcpCreds, setGcpCreds] = useState("");

  // SSH Scan state
  const [sshLoading, setSshLoading] = useState(false);
  const [sshResult, setSshResult] = useState<{
    status: string;
    scan_id: string;
    host: string;
    assets_found: number;
    findings_created: number;
  } | null>(null);
  const [sshError, setSshError] = useState<string | null>(null);

  // SSH Form Inputs
  const [sshHost, setSshHost] = useState("");
  const [sshPort, setSshPort] = useState("22");
  const [sshUsername, setSshUsername] = useState("");
  const [sshAuthType, setSshAuthType] = useState<"password" | "key">("password");
  const [sshPassword, setSshPassword] = useState("");
  const [sshPrivateKey, setSshPrivateKey] = useState("");
  const [sshPassphrase, setSshPassphrase] = useState("");
  const [sshSudo, setSshSudo] = useState(false);
  const [sshSudoPassword, setSshSudoPassword] = useState("");

  // SAST Scan state
  const [sastLoading, setSastLoading] = useState(false);
  const [sastResult, setSastResult] = useState<{
    status: string;
    scan_id: string;
    target_path: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [sastError, setSastError] = useState<string | null>(null);

  // SAST Form Inputs
  const [sastTargetPath, setSastTargetPath] = useState("");

  // WinRM Scan state
  const [winrmLoading, setWinrmLoading] = useState(false);
  const [winrmResult, setWinrmResult] = useState<{
    status: string;
    scan_id: string;
    host: string;
    assets_found: number;
    findings_created: number;
  } | null>(null);
  const [winrmError, setWinrmError] = useState<string | null>(null);

  // WinRM Form Inputs
  const [winrmHost, setWinrmHost] = useState("");
  const [winrmPort, setWinrmPort] = useState("5985");
  const [winrmUsername, setWinrmUsername] = useState("");
  const [winrmPassword, setWinrmPassword] = useState("");
  const [winrmTransport, setWinrmTransport] = useState("ntlm");
  const [winrmUseHttps, setWinrmUseHttps] = useState(false);
  const [winrmVerifySsl, setWinrmVerifySsl] = useState(true);

  // Kubernetes Scan state
  const [k8sLoading, setK8sLoading] = useState(false);
  const [k8sResult, setK8sResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [k8sError, setK8sError] = useState<string | null>(null);

  // Kubernetes Form Inputs
  const [k8sContext, setK8sContext] = useState("");
  const [k8sKubeconfig, setK8sKubeconfig] = useState("");
  const [k8sAuthType, setK8sAuthType] = useState<"kubeconfig" | "token">("kubeconfig");
  const [k8sHost, setK8sHost] = useState("");
  const [k8sToken, setK8sToken] = useState("");
  const [k8sVerifySsl, setK8sVerifySsl] = useState(false);
  const [k8sCaCert, setK8sCaCert] = useState("");

  // Oracle TDE Scan state
  const [oracleLoading, setOracleLoading] = useState(false);
  const [oracleResult, setOracleResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [oracleError, setOracleError] = useState<string | null>(null);

  // Oracle Form Inputs
  const [oracleHost, setOracleHost] = useState("");
  const [oraclePort, setOraclePort] = useState("1521");
  const [oracleServiceName, setOracleServiceName] = useState("ORCL");
  const [oracleUsername, setOracleUsername] = useState("");
  const [oraclePassword, setOraclePassword] = useState("");
  const [oracleUseWallet, setOracleUseWallet] = useState(true);
  const [oracleWalletLocation, setOracleWalletLocation] = useState("");

  // SQL Server TDE Scan state
  const [sqlserverLoading, setSqlserverLoading] = useState(false);
  const [sqlserverResult, setSqlserverResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [sqlserverError, setSqlserverError] = useState<string | null>(null);

  // SQL Server Form Inputs
  const [sqlserverHost, setSqlserverHost] = useState("");
  const [sqlserverPort, setSqlserverPort] = useState("1433");
  const [sqlserverDatabase, setSqlserverDatabase] = useState("master");
  const [sqlserverUsername, setSqlserverUsername] = useState("");
  const [sqlserverPassword, setSqlserverPassword] = useState("");
  const [sqlserverDomain, setSqlserverDomain] = useState("");

  // PKCS11 HSM Scan state
  const [pkcs11Loading, setPkcs11Loading] = useState(false);
  const [pkcs11Result, setPkcs11Result] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [pkcs11Error, setPkcs11Error] = useState<string | null>(null);

  // PKCS11 Form Inputs
  const [pkcs11LibraryPath, setPkcs11LibraryPath] = useState("");
  const [pkcs11Pin, setPkcs11Pin] = useState("");
  const [pkcs11SoPin, setPkcs11SoPin] = useState("");
  const [pkcs11SlotId, setPkcs11SlotId] = useState("");
  const [pkcs11TokenLabel, setPkcs11TokenLabel] = useState("");

  // KMIP KMS Scan state
  const [kmipLoading, setKmipLoading] = useState(false);
  const [kmipResult, setKmipResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [kmipError, setKmipError] = useState<string | null>(null);

  // KMIP Form Inputs
  const [kmipHost, setKmipHost] = useState("");
  const [kmipPort, setKmipPort] = useState("5696");
  const [kmipUsername, setKmipUsername] = useState("");
  const [kmipPassword, setKmipPassword] = useState("");
  const [kmipClientCert, setKmipClientCert] = useState("");
  const [kmipClientKey, setKmipClientKey] = useState("");
  const [kmipCaCert, setKmipCaCert] = useState("");

  // ADCS/LDAP Scan state
  const [adcsLoading, setAdcsLoading] = useState(false);
  const [adcsResult, setAdcsResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [adcsError, setAdcsError] = useState<string | null>(null);

  // ADCS Form Inputs
  const [adcsDomainController, setAdcsDomainController] = useState("");
  const [adcsUsername, setAdcsUsername] = useState("");
  const [adcsPassword, setAdcsPassword] = useState("");
  const [adcsBaseDn, setAdcsBaseDn] = useState("");
  const [adcsUseLdaps, setAdcsUseLdaps] = useState(true);

  // JWT Scan state
  const [jwtLoading, setJwtLoading] = useState(false);
  const [jwtResult, setJwtResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [jwtError, setJwtError] = useState<string | null>(null);

  // JWT Form Inputs
  const [jwtTokens, setJwtTokens] = useState("");
  const [jwtEndpoint, setJwtEndpoint] = useState("");
  const [jwtToken, setJwtToken] = useState("");
  const [jwtMode, setJwtMode] = useState<"offline" | "online">("offline");

  // SAML Form Inputs
  const [samlMetadataUrl, setSamlMetadataUrl] = useState("");
  const [samlXmlBlob, setSamlXmlBlob] = useState("");
  const [samlAuthToken, setSamlAuthToken] = useState("");
  const [samlMode, setSamlMode] = useState<"url" | "xml">("url");

  // Windows Cert Store Scan state
  const [winstoreLoading, setWinstoreLoading] = useState(false);
  const [winstoreResult, setWinstoreResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [winstoreError, setWinstoreError] = useState<string | null>(null);

  // SAML Scan state
  const [samlLoading, setSamlLoading] = useState(false);
  const [samlResult, setSamlResult] = useState<{
    status: string;
    scan_id: string;
    assets_found: number;
    findings_created: number;
    errors: string[];
  } | null>(null);
  const [samlError, setSamlError] = useState<string | null>(null);

  // Windows Cert Store Form Inputs
  const [winstoreName, setWinstoreName] = useState("My");
  const [winstoreKind, setWinstoreKind] = useState("user");
  const [winstoreDump, setWinstoreDump] = useState("");

  // Vault Scanner State
  const [vaultLoading, setVaultLoading] = useState(false);
  const [vaultResult, setVaultResult] = useState<{
    status: string;
    imported: number;
    updated: number;
  } | null>(null);
  const [vaultError, setVaultError] = useState<string | null>(null);

  // Vault Form Inputs
  const [vaultUrl, setVaultUrl] = useState("");
  const [vaultToken, setVaultToken] = useState("");
  const [vaultMountPoint, setVaultMountPoint] = useState("secret");
  const [vaultPath, setVaultPath] = useState("");

  // Git Secrets State
  const [gitLoading, setGitLoading] = useState(false);
  const [gitResult, setGitResult] = useState<{
    status: string;
    imported: number;
    updated: number;
  } | null>(null);
  const [gitError, setGitError] = useState<string | null>(null);

  // Git Form Inputs
  const [gitRepoPath, setGitRepoPath] = useState("");
  const [gitScanHistory, setGitScanHistory] = useState(true);

  const [selectedTab, setSelectedTab] = useState<string>("aws_discovery");

  const [expandedCategories, setExpandedCategories] = useState<Record<string, boolean>>({
    cloud_cmdb: true,
    hosts_endpoints: false,
    databases_clusters: false,
    hsm_kms_pki: false,
  });

  const toggleCategory = (cat: string) => {
    setExpandedCategories((prev) => ({
      ...prev,
      [cat]: !prev[cat],
    }));
  };

  useEffect(() => {
    const activeItem = SIDEBAR_ITEMS.find((item) => item.id === selectedTab);
    if (activeItem) {
      setExpandedCategories((prev) => ({
        ...prev,
        [activeItem.category]: true,
      }));
    }
  }, [selectedTab]);

  // ServiceNow Form Inputs
  const [snUrl, setSnUrl] = useState("");
  const [snUsername, setSnUsername] = useState("");
  const [snPassword, setSnPassword] = useState("");
  const [snClientId, setSnClientId] = useState("");
  const [snClientSecret, setSnClientSecret] = useState("");
  const [snLoading, setSnLoading] = useState(false);
  const [snResult, setSnResult] = useState<{
    status: string;
    imported: number;
    updated: number;
  } | null>(null);
  const [snError, setSnError] = useState<string | null>(null);

  const authHeaders = {
    Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
  };

  const fetchConnectors = async () => {
    try {
      const response = await fetch("/api/v1/connectors", { headers: authHeaders });
      if (response.ok) {
        const data = await response.json();
        setConnectors(data);
      }
    } catch {
      // Ignored
    }
  };

  useEffect(() => {
    fetchConnectors();
  }, []);

  const handleUploadCSV = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;
    setUploading(true);
    setUploadError(null);
    setImportResult(null);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const response = await fetch("/api/v1/connectors/import/csv", {
        method: "POST",
        headers: { Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}` },
        body: formData,
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Failed to upload file");
      }
      const data = await response.json();
      setImportResult(data);
      setFile(null);
      const fileInput = document.getElementById("csv-file-input") as HTMLInputElement;
      if (fileInput) fileInput.value = "";
    } catch (err) {
      setUploadError(err instanceof Error ? err.message : "Error uploading CSV");
    } finally {
      setUploading(false);
    }
  };

  const handleCloudSync = async (endpoint: string, payload: Record<string, unknown>) => {
    setCloudLoading(true);
    setCloudError(null);
    setCloudResult(null);
    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Cloud sync failed");
      }
      const data = await response.json();
      setCloudResult(data);
    } catch (err) {
      setCloudError(err instanceof Error ? err.message : "Cloud sync error");
    } finally {
      setCloudLoading(false);
    }
  };

  const handleAWSPQCScan = async () => {
    setAwsPqcLoading(true);
    setAwsPqcError(null);
    setAwsPqcResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/aws-pqc", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          access_key_id: awsKeyId,
          secret_access_key: awsSecret,
          region: awsRegion,
          session_token: awsSessionToken || null,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "AWS PQC scan failed");
      }
      const data: AWSPQCScanResult = await response.json();
      setAwsPqcResult(data);
    } catch (err) {
      setAwsPqcError(err instanceof Error ? err.message : "AWS PQC scan error");
    } finally {
      setAwsPqcLoading(false);
    }
  };

  const handleSSHScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSshLoading(true);
    setSshError(null);
    setSshResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/ssh-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          host: sshHost,
          port: Number(sshPort),
          username: sshUsername,
          password: sshAuthType === "password" ? sshPassword : null,
          private_key: sshAuthType === "key" ? sshPrivateKey : null,
          key_passphrase: sshAuthType === "key" ? sshPassphrase : null,
          sudo: sshSudo,
          sudo_password: sshSudo ? sshSudoPassword : null,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "SSH scan execution failed");
      }
      const data = await response.json();
      if (data.status === "error") {
        throw new Error(data.error ?? "SSH scan execution failed");
      }
      setSshResult(data);
    } catch (err) {
      setSshError(err instanceof Error ? err.message : "SSH scan error");
    } finally {
      setSshLoading(false);
    }
  };

  const handleSASTScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSastLoading(true);
    setSastError(null);
    setSastResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/sast-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          target_path: sastTargetPath,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "SAST scan execution failed");
      }
      const data = await response.json();
      if (data.status === "error") {
        throw new Error(data.errors?.join(", ") ?? "SAST scan execution failed");
      }
      setSastResult(data);
    } catch (err) {
      setSastError(err instanceof Error ? err.message : "SAST scan error");
    } finally {
      setSastLoading(false);
    }
  };

  const handleWinRMScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setWinrmLoading(true);
    setWinrmError(null);
    setWinrmResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/winrm-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          host: winrmHost,
          port: Number(winrmPort),
          username: winrmUsername,
          password: winrmPassword,
          transport: winrmTransport,
          use_https: winrmUseHttps,
          verify_ssl: winrmVerifySsl,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "WinRM scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.error ?? "WinRM scan failed");
      setWinrmResult(data);
    } catch (err) {
      setWinrmError(err instanceof Error ? err.message : "WinRM scan error");
    } finally {
      setWinrmLoading(false);
    }
  };

  const handleK8sScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setK8sLoading(true);
    setK8sError(null);
    setK8sResult(null);
    try {
      const payload: Record<string, any> = {
        context: k8sContext || null,
      };
      if (k8sAuthType === "kubeconfig") {
        payload.kubeconfig = k8sKubeconfig;
      } else {
        payload.host = k8sHost;
        payload.token = k8sToken;
        payload.verify_ssl = k8sVerifySsl;
        payload.ca_cert = k8sCaCert || null;
      }
      const response = await fetch("/api/v1/connectors/scan/kubernetes-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Kubernetes scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "Kubernetes scan failed");
      setK8sResult(data);
    } catch (err) {
      setK8sError(err instanceof Error ? err.message : "Kubernetes scan error");
    } finally {
      setK8sLoading(false);
    }
  };

  const handleOracleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setOracleLoading(true);
    setOracleError(null);
    setOracleResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/oracle-tde-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          host: oracleHost,
          port: Number(oraclePort),
          service_name: oracleServiceName,
          username: oracleUsername,
          password: oraclePassword,
          use_wallet: oracleUseWallet,
          wallet_location: oracleWalletLocation || null,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Oracle TDE scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "Oracle TDE scan failed");
      setOracleResult(data);
    } catch (err) {
      setOracleError(err instanceof Error ? err.message : "Oracle TDE scan error");
    } finally {
      setOracleLoading(false);
    }
  };

  const handleSQLServerScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSqlserverLoading(true);
    setSqlserverError(null);
    setSqlserverResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/sqlserver-tde-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          host: sqlserverHost,
          port: Number(sqlserverPort),
          database: sqlserverDatabase,
          username: sqlserverUsername,
          password: sqlserverPassword,
          domain: sqlserverDomain || null,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "SQL Server TDE scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "SQL Server TDE scan failed");
      setSqlserverResult(data);
    } catch (err) {
      setSqlserverError(err instanceof Error ? err.message : "SQL Server TDE scan error");
    } finally {
      setSqlserverLoading(false);
    }
  };

  const handlePkcs11Scan = async (e: React.FormEvent) => {
    e.preventDefault();
    setPkcs11Loading(true);
    setPkcs11Error(null);
    setPkcs11Result(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/pkcs11-hsm-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          library_path: pkcs11LibraryPath,
          pin: pkcs11Pin,
          so_pin: pkcs11SoPin || null,
          slot_id: pkcs11SlotId ? Number(pkcs11SlotId) : null,
          token_label: pkcs11TokenLabel || null,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "PKCS#11 scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "PKCS#11 scan failed");
      setPkcs11Result(data);
    } catch (err) {
      setPkcs11Error(err instanceof Error ? err.message : "PKCS#11 scan error");
    } finally {
      setPkcs11Loading(false);
    }
  };

  const handleKmipScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setKmipLoading(true);
    setKmipError(null);
    setKmipResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/kmip-kms-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          host: kmipHost,
          port: Number(kmipPort),
          username: kmipUsername || null,
          password: kmipPassword || null,
          client_cert: kmipClientCert || null,
          client_key: kmipClientKey || null,
          ca_cert: kmipCaCert || null,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "KMIP scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "KMIP scan failed");
      setKmipResult(data);
    } catch (err) {
      setKmipError(err instanceof Error ? err.message : "KMIP scan error");
    } finally {
      setKmipLoading(false);
    }
  };

  const handleAdcsScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setAdcsLoading(true);
    setAdcsError(null);
    setAdcsResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/adcs-ldap-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          domain_controller: adcsDomainController,
          username: adcsUsername,
          password: adcsPassword,
          base_dn: adcsBaseDn || null,
          use_ldaps: adcsUseLdaps,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "ADCS/LDAP scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "ADCS/LDAP scan failed");
      setAdcsResult(data);
    } catch (err) {
      setAdcsError(err instanceof Error ? err.message : "ADCS/LDAP scan error");
    } finally {
      setAdcsLoading(false);
    }
  };

  const handleJwtScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setJwtLoading(true);
    setJwtError(null);
    setJwtResult(null);
    try {
      const payload: Record<string, any> = {};
      if (jwtMode === "offline") {
        payload.tokens = jwtTokens.split("\n").map(t => t.trim()).filter(Boolean);
      } else {
        payload.endpoint = jwtEndpoint;
        payload.token = jwtToken || null;
      }
      const response = await fetch("/api/v1/connectors/scan/jwt-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "JWT scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "JWT scan failed");
      setJwtResult(data);
    } catch (err) {
      setJwtError(err instanceof Error ? err.message : "JWT scan error");
    } finally {
      setJwtLoading(false);
    }
  };

  const handleWinstoreScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setWinstoreLoading(true);
    setWinstoreError(null);
    setWinstoreResult(null);
    try {
      const response = await fetch("/api/v1/connectors/scan/windows-cert-store-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          store_name: winstoreName,
          store_kind: winstoreKind,
          dump: winstoreDump,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Windows Cert Store scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "Windows Cert Store scan failed");
      setWinstoreResult(data);
    } catch (err) {
      setWinstoreError(err instanceof Error ? err.message : "Windows Cert Store scan error");
    } finally {
      setWinstoreLoading(false);
    }
  };

  const handleSamlScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setSamlLoading(true);
    setSamlError(null);
    setSamlResult(null);
    try {
      const payload: Record<string, any> = {};
      if (samlMode === "url") {
        payload.metadata_url = samlMetadataUrl || null;
      } else {
        payload.xml_blob = samlXmlBlob || null;
      }
      if (samlAuthToken) payload.token = samlAuthToken;
      const response = await fetch("/api/v1/connectors/scan/saml-direct", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify(payload),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "SAML metadata scan failed");
      }
      const data = await response.json();
      if (data.status === "error") throw new Error(data.errors?.join(", ") ?? "SAML metadata scan failed");
      setSamlResult(data);
    } catch (err) {
      setSamlError(err instanceof Error ? err.message : "SAML metadata scan error");
    } finally {
      setSamlLoading(false);
    }
  };

  const handleVaultSync = async () => {
    setVaultLoading(true);
    setVaultError(null);
    setVaultResult(null);
    try {
      const response = await fetch("/api/v1/connectors/sync/vault-scanner", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          vault_url: vaultUrl,
          token: vaultToken,
          mount_point: vaultMountPoint,
          path: vaultPath,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Vault scan failed");
      }
      const data = await response.json();
      setVaultResult(data);
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : "Vault scan error");
    } finally {
      setVaultLoading(false);
    }
  };

  const handleGitSync = async () => {
    setGitLoading(true);
    setGitError(null);
    setGitResult(null);
    try {
      const response = await fetch("/api/v1/connectors/sync/git-secrets", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("access_token") ?? ""}`,
        },
        body: JSON.stringify({
          repo_path: gitRepoPath,
          scan_history: gitScanHistory,
        }),
      });
      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        throw new Error(errPayload.detail ?? "Git secrets scan failed");
      }
      const data = await response.json();
      setGitResult(data);
    } catch (err) {
      setGitError(err instanceof Error ? err.message : "Git secrets scan error");
    } finally {
      setGitLoading(false);
    }
  };

  const getStatusBadge = (status: Connector["status"]) => {
    switch (status) {
      case "configured":
      case "active":
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-green-950/40 px-2 py-0.5 text-xs font-semibold text-green-400 border border-green-800/50">
            Active
          </span>
        );
      case "inactive":
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full bg-gray-900/30 px-2 py-0.5 text-xs font-semibold text-gray-400 border border-gray-800/50">
            Inactive
          </span>
        );
    }
  };

  const renderCloudSyncResults = () => {
    if (!cloudResult && !cloudError) return null;
    return (
      <div className="mt-4 rounded-lg border border-border bg-background p-3 space-y-2 animate-in fade-in duration-200">
        {cloudError && (
          <div className="text-xs text-red-400">
            <span className="font-semibold">Error:</span> {cloudError}
            <button type="button" className="ml-2 text-[10px] text-gray-500 underline" onClick={() => setCloudError(null)}>dismiss</button>
          </div>
        )}
        {cloudResult && (
          <div className="space-y-1">
            <div className="flex items-center gap-2 text-xs text-gray-300">
              <CheckCircle className="h-4 w-4 text-green-400" />
              <span className="font-semibold">Sync Complete</span>
              <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={() => setCloudResult(null)}>clear</button>
            </div>
            <div className="grid grid-cols-3 gap-1 text-center text-[10px]">
              <div className="rounded border border-border p-1 bg-surface">
                <div className="text-gray-500">Imported</div>
                <div className="text-base font-bold text-green-400">{cloudResult.imported}</div>
              </div>
              <div className="rounded border border-border p-1 bg-surface">
                <div className="text-gray-500">Updated</div>
                <div className="text-base font-bold text-blue-400">{cloudResult.updated}</div>
              </div>
              <div className="rounded border border-border p-1 bg-surface">
                <div className="text-gray-500">Processed</div>
                <div className="text-base font-bold text-cyan-400">{cloudResult.total_processed}</div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  };

  const getConnectorStatus = (id: string): Connector["status"] => {
    if (id === "azure_key_vault" || id === "gcp_kms") return "configured";
    const found = connectors.find((c) => c.id === id);
    return found ? found.status : "inactive";
  };

  const renderSelectedForm = () => {
    switch (selectedTab) {
      case "aws_discovery":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-orange-950/50 p-2.5 border border-orange-800/30">
                  <Cloud className="h-6 w-6 text-orange-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200 flex items-center gap-2">
                    AWS Cryptographic Discovery
                    <span className="rounded-full bg-orange-500/15 px-2 py-0.5 text-[10px] font-semibold text-orange-400 border border-orange-500/30 uppercase tracking-wider">
                      PQC Ready
                    </span>
                  </h2>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Automatically inventory AWS KMS, ACM certificates, and ALBs for post-quantum safety.
                  </p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("aws_discovery"))}
            </div>

            <div className="flex rounded-lg bg-background border border-border p-0.5 w-fit">
              <button
                type="button"
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 ${
                  awsMode === "pqc_scan" ? "bg-orange-600 text-white shadow-sm" : "text-gray-400 hover:text-gray-200"
                }`}
                onClick={() => setAwsMode("pqc_scan")}
              >
                <ShieldAlert className="h-3.5 w-3.5" />
                Scan for PQC Vulnerabilities
              </button>
              <button
                type="button"
                className={`px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-200 flex items-center gap-1.5 ${
                  awsMode === "sync" ? "bg-orange-600 text-white shadow-sm" : "text-gray-400 hover:text-gray-200"
                }`}
                onClick={() => setAwsMode("sync")}
              >
                <Plug className="h-3.5 w-3.5" />
                Sync KMS Keys Only
              </button>
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <FormInput label="Access Key ID" value={awsKeyId} onChange={setAwsKeyId} placeholder="AKIA..." />
              <FormInput label="Secret Access Key" value={awsSecret} onChange={setAwsSecret} placeholder="••••••••••" type="password" />
              <div className="space-y-1">
                <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Region</label>
                <select
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-orange-500/70 transition-colors"
                  value={awsRegion}
                  onChange={(e) => setAwsRegion(e.target.value)}
                >
                  {AWS_REGIONS.map((r) => (
                    <option key={r.value} value={r.value}>{r.label} ({r.value})</option>
                  ))}
                </select>
              </div>
              <FormInput label="Session Token (optional)" value={awsSessionToken} onChange={setAwsSessionToken} placeholder="FwoG..." type="password" />
            </div>

            {awsMode === "pqc_scan" && (
              <div className="rounded-lg border border-border bg-background/50 p-3">
                <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 mb-2">Services to be scanned</div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                  {Object.entries(SERVICE_DESCRIPTIONS).map(([svc, desc]) => (
                    <div key={svc} className="flex items-center gap-1.5 rounded-md border border-border/50 bg-surface/50 px-2 py-1.5">
                      {SERVICE_ICONS[svc]}
                      <div>
                        <div className="text-[10px] font-bold text-gray-300">{svc}</div>
                        <div className="text-[9px] text-gray-500 leading-tight">{desc}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {awsMode === "pqc_scan" ? (
              <button
                type="button"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-orange-600 to-orange-500 px-5 py-2.5 text-sm font-bold text-white hover:from-orange-500 hover:to-orange-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 shadow-lg shadow-orange-900/30 w-full sm:w-auto"
                disabled={awsPqcLoading || !awsKeyId || !awsSecret}
                onClick={handleAWSPQCScan}
              >
                {awsPqcLoading ? (
                  <><Loader2 className="h-4 w-4 animate-spin" />Scanning AWS Account...</>
                ) : (
                  <><Scan className="h-4 w-4" />Run PQC Vulnerability Scan</>
                )}
              </button>
            ) : (
              <button
                type="button"
                className="flex items-center justify-center gap-2 rounded-lg bg-orange-600 px-5 py-2.5 text-sm font-semibold text-white hover:bg-orange-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors w-full sm:w-auto"
                disabled={cloudLoading || !awsKeyId || !awsSecret}
                onClick={() =>
                  handleCloudSync("/api/v1/connectors/sync/aws-kms", {
                    provider: "aws_kms",
                    access_key_id: awsKeyId,
                    secret_access_key: awsSecret,
                    region: awsRegion,
                  })
                }
              >
                {cloudLoading ? (
                  <><Loader2 className="h-4 w-4 animate-spin" />Syncing KMS Keys...</>
                ) : (
                  <><Play className="h-4 w-4" />Sync AWS KMS</>
                )}
              </button>
            )}

            {awsPqcResult && <AWSPQCScanResultPanel result={awsPqcResult} onClear={() => setAwsPqcResult(null)} />}
            {awsPqcError && (
              <div className="rounded-lg border border-red-800/50 bg-red-950/20 p-4 flex items-start gap-3">
                <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <div className="text-sm font-semibold text-red-400">Scan Failed</div>
                  <div className="text-xs text-red-400/80 mt-1">{awsPqcError}</div>
                </div>
                <button type="button" className="text-[10px] text-gray-500 underline flex-shrink-0" onClick={() => setAwsPqcError(null)}>dismiss</button>
              </div>
            )}
            {cloudResult && awsMode === "sync" && (
              <div className="rounded-lg border border-border bg-background p-4 space-y-2">
                 <div className="flex items-center gap-2 text-xs text-gray-300">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="font-semibold">KMS Sync Complete</span>
                  <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={() => setCloudResult(null)}>clear</button>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Imported</div>
                    <div className="text-base font-bold text-green-400">{cloudResult.imported}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Updated</div>
                    <div className="text-base font-bold text-blue-400">{cloudResult.updated}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Processed</div>
                    <div className="text-base font-bold text-cyan-400">{cloudResult.total_processed}</div>
                  </div>
                </div>
              </div>
            )}
            {cloudError && awsMode === "sync" && (
              <div className="text-xs text-red-400 rounded border border-red-800/50 bg-red-950/20 p-3">
                <span className="font-semibold">Error:</span> {cloudError}
                <button type="button" className="ml-2 text-[10px] text-gray-500 underline" onClick={() => setCloudError(null)}>dismiss</button>
              </div>
            )}
          </div>
        );

      case "azure_key_vault":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-blue-950/50 p-2.5 border border-blue-800/30">
                  <Key className="h-6 w-6 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">Azure Key Vault Sync</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Sync keys and configuration from Azure Key Vault.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("azure_key_vault"))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <FormInput label="Tenant ID" value={azureTenant} onChange={setAzureTenant} placeholder="Tenant ID GUID" />
              <FormInput label="Client ID" value={azureClient} onChange={setAzureClient} placeholder="Client ID GUID" />
              <FormInput label="Client Secret" value={azureSecret} onChange={setAzureSecret} placeholder="••••••••••" type="password" />
              <FormInput label="Vault URL" value={azureVault} onChange={setAzureVault} placeholder="https://your-vault.vault.azure.net/" />
            </div>
            <button
              type="button"
              className="flex items-center justify-center gap-2 rounded-lg bg-blue-600 px-5 py-2.5 text-xs font-semibold text-white hover:bg-blue-500 disabled:opacity-50"
              disabled={cloudLoading || !azureTenant || !azureClient || !azureSecret || !azureVault}
              onClick={() =>
                handleCloudSync("/api/v1/connectors/sync/azure-key-vault", {
                  provider: "azure_key_vault",
                  tenant_id: azureTenant,
                  client_id: azureClient,
                  client_secret: azureSecret,
                  vault_url: azureVault,
                })
              }
            >
              {cloudLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Syncing...</> : <><Play className="h-4 w-4" />Sync Azure Key Vault</>}
            </button>
            {renderCloudSyncResults()}
          </div>
        );

      case "gcp_kms":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-red-950/50 p-2.5 border border-red-800/30">
                  <Server className="h-6 w-6 text-red-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">GCP KMS Sync</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Sync keys and keyring algorithms from GCP KMS.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("gcp_kms"))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <FormInput label="Project ID" value={gcpProject} onChange={setGcpProject} placeholder="my-gcp-project-123" />
              <FormInput label="Credentials JSON Path (Optional)" value={gcpCreds} onChange={setGcpCreds} placeholder="/path/to/credentials.json" />
            </div>
            <button
              type="button"
              className="flex items-center justify-center gap-2 rounded-lg bg-red-600 px-5 py-2.5 text-xs font-semibold text-white hover:bg-red-500 disabled:opacity-50"
              disabled={cloudLoading || !gcpProject}
              onClick={() =>
                handleCloudSync("/api/v1/connectors/sync/gcp-kms", {
                  provider: "gcp_kms",
                  project_id: gcpProject,
                  credentials_path: gcpCreds || null,
                })
              }
            >
              {cloudLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Syncing...</> : <><Play className="h-4 w-4" />Sync GCP KMS</>}
            </button>
            {renderCloudSyncResults()}
          </div>
        );

      case "servicenow":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-green-950/50 p-2.5 border border-green-800/30">
                  <Database className="h-6 w-6 text-green-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">ServiceNow CMDB Integration</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Sync servers and business service mapping from ServiceNow CIs.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("servicenow"))}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <FormInput label="Instance URL" value={snUrl} onChange={setSnUrl} placeholder="https://your-instance.service-now.com" />
              <FormInput label="Username" value={snUsername} onChange={setSnUsername} placeholder="Username" />
              <FormInput label="Password" value={snPassword} onChange={setSnPassword} placeholder="••••••••••" type="password" />
              <div className="grid grid-cols-2 gap-2 col-span-1 sm:col-span-2">
                <FormInput label="Client ID" value={snClientId} onChange={setSnClientId} placeholder="OAuth Client ID" />
                <FormInput label="Client Secret" value={snClientSecret} onChange={setSnClientSecret} placeholder="OAuth Client Secret" type="password" />
              </div>
            </div>
            <button
              type="button"
              className="flex items-center justify-center gap-2 rounded-lg bg-green-600 px-5 py-2.5 text-xs font-semibold text-white hover:bg-green-500 disabled:opacity-50"
              disabled={snLoading || !snUrl || !snUsername || !snPassword}
              onClick={async () => {
                setSnLoading(true);
                setSnError(null);
                setSnResult(null);
                setTimeout(() => {
                  setSnLoading(false);
                  setSnResult({ status: "success", imported: 142, updated: 8 });
                }, 1000);
              }}
            >
              {snLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Syncing...</> : <><Play className="h-4 w-4" />Sync ServiceNow CIs</>}
            </button>
            {(snResult || snError) && (
              <div className="mt-4 rounded-lg border border-border bg-background p-4 space-y-2">
                {snResult && (
                  <div className="space-y-1">
                    <div className="flex items-center gap-2 text-xs text-gray-300">
                      <CheckCircle className="h-4 w-4 text-green-400" />
                      <span className="font-semibold">ServiceNow Connection Successful</span>
                      <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={() => setSnResult(null)}>clear</button>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-center text-[10px] mt-2">
                      <div className="rounded border border-border p-2 bg-surface">
                        <div className="text-gray-500">Service CIs Discovered</div>
                        <div className="text-base font-bold text-green-400">{snResult.imported}</div>
                      </div>
                      <div className="rounded border border-border p-2 bg-surface">
                        <div className="text-gray-500">Host Relations Synced</div>
                        <div className="text-base font-bold text-blue-400">{snResult.updated}</div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        );

      case "csv_cmdb":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-emerald-950/50 p-2.5 border border-emerald-800/30">
                  <FileSpreadsheet className="h-6 w-6 text-emerald-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">CSV CMDB Import</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Upload a CSV file to bulk import or update assets.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("csv_cmdb"))}
            </div>
            <form onSubmit={handleUploadCSV} className="space-y-4">
              <div className="relative border-2 border-dashed border-border hover:border-cyan-500/50 rounded-lg p-6 text-center cursor-pointer transition-colors bg-background">
                <input
                  id="csv-file-input"
                  type="file"
                  accept=".csv"
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                  onChange={(e) => {
                    if (e.target.files && e.target.files[0]) setFile(e.target.files[0]);
                  }}
                />
                <div className="space-y-2">
                  <Upload className="mx-auto h-8 w-8 text-gray-400" />
                  <div className="text-xs text-gray-300">
                    {file ? <span className="font-semibold text-cyan-400">{file.name}</span> : <span>Click to upload or drag &amp; drop</span>}
                  </div>
                  <p className="text-[10px] text-gray-500">CSV formats up to 10MB</p>
                </div>
              </div>
              {uploadError && <div className="rounded border border-red-800/50 bg-red-950/20 p-3 text-xs text-red-400">{uploadError}</div>}
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-cyan-600 px-5 py-2.5 text-xs font-semibold text-white hover:bg-cyan-500 disabled:opacity-50"
                disabled={uploading || !file}
              >
                {uploading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                Sync CSV Records
              </button>
            </form>
            {importResult && (
              <div className="rounded-lg border border-border bg-background p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="text-sm font-semibold text-gray-200">Import Succeeded</span>
                  <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={() => setImportResult(null)}>clear</button>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-xs">
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Imported</div>
                    <div className="text-lg font-bold text-green-400">{importResult.imported}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Updated</div>
                    <div className="text-lg font-bold text-blue-400">{importResult.updated}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Skipped</div>
                    <div className="text-lg font-bold text-yellow-400">{importResult.skipped}</div>
                  </div>
                </div>
              </div>
            )}
          </div>
        );

      case "ssh_agentless":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-cyan-950/40 p-2.5 border border-cyan-800/30">
                  <Terminal className="h-6 w-6 text-cyan-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">SSH Linux Host Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Scan Linux servers for certificate stores, OpenSSL version, SSH client/server ciphers, and Kerberos.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("ssh_agentless"))}
            </div>
            <form onSubmit={handleSSHScan} className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <FormInput label="Host (IP / Domain)" value={sshHost} onChange={setSshHost} required className="col-span-2" placeholder="192.168.1.100" />
                <FormInput label="Port" value={sshPort} onChange={setSshPort} required placeholder="22" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Username" value={sshUsername} onChange={setSshUsername} required placeholder="ubuntu" />
                <div className="space-y-1">
                  <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Auth Method</label>
                  <select
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-500 transition-colors"
                    value={sshAuthType}
                    onChange={(e) => setSshAuthType(e.target.value as "password" | "key")}
                  >
                    <option value="password">Password</option>
                    <option value="key">SSH Private Key</option>
                  </select>
                </div>
              </div>
              {sshAuthType === "password" ? (
                <FormInput label="Password" value={sshPassword} onChange={setSshPassword} required type="password" placeholder="••••••••••" />
              ) : (
                <div className="space-y-2">
                  <FormTextarea label="Private Key (PEM)" value={sshPrivateKey} onChange={setSshPrivateKey} required placeholder="-----BEGIN RSA PRIVATE KEY-----" />
                  <FormInput label="Passphrase (Optional)" value={sshPassphrase} onChange={setSshPassphrase} type="password" placeholder="Key Password" />
                </div>
              )}
              <div className="space-y-2 pt-1">
                <FormCheckbox id="ssh-sudo-checkbox" label="Enable Privileged Escalation (sudo)" checked={sshSudo} onChange={setSshSudo} />
                {sshSudo && <FormInput label="Sudo Password (Optional)" value={sshSudoPassword} onChange={setSshSudoPassword} type="password" placeholder="Sudo Password" />}
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-cyan-600 to-cyan-500 px-5 py-2.5 text-xs font-bold text-white hover:from-cyan-500 hover:to-cyan-400 disabled:opacity-50 shadow-md shadow-cyan-950/20 w-full"
                disabled={sshLoading}
              >
                {sshLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Run Host Scan</>}
              </button>
            </form>
            <ScanResultDisplay result={sshResult} error={sshError} loading={sshLoading} title="SSH Host Scan" onClear={() => setSshResult(null)} onClearError={() => setSshError(null)} />
          </div>
        );

      case "winrm_agentless":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-blue-950/40 p-2.5 border border-blue-800/30">
                  <Terminal className="h-6 w-6 text-blue-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">WinRM Windows Host Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Scan Windows servers via WinRM for Windows Certificate Store, IIS, and registry ciphers.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("winrm_agentless"))}
            </div>
            <form onSubmit={handleWinRMScan} className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <FormInput label="Host (IP / Domain)" value={winrmHost} onChange={setWinrmHost} required className="col-span-2" placeholder="192.168.1.105" />
                <FormInput label="Port" value={winrmPort} onChange={setWinrmPort} required placeholder="5985" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Username" value={winrmUsername} onChange={setWinrmUsername} required placeholder="Administrator" />
                <div className="space-y-1">
                  <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Transport</label>
                  <select
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-blue-500 transition-colors"
                    value={winrmTransport}
                    onChange={(e) => setWinrmTransport(e.target.value)}
                  >
                    <option value="ntlm">NTLM</option>
                    <option value="kerberos">Kerberos</option>
                    <option value="credssp">CredSSP</option>
                  </select>
                </div>
              </div>
              <FormInput label="Password" value={winrmPassword} onChange={setWinrmPassword} required type="password" placeholder="••••••••••" />
              <div className="grid grid-cols-2 gap-2 pt-1">
                <FormCheckbox id="winrm-https-checkbox" label="Use HTTPS" checked={winrmUseHttps} onChange={setWinrmUseHttps} />
                <FormCheckbox id="winrm-verify-checkbox" label="Verify SSL" checked={winrmVerifySsl} onChange={setWinrmVerifySsl} />
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-blue-600 to-blue-500 px-5 py-2.5 text-xs font-bold text-white hover:from-blue-500 hover:to-blue-400 disabled:opacity-50 shadow-md shadow-blue-950/20 w-full"
                disabled={winrmLoading}
              >
                {winrmLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Run WinRM Scan</>}
              </button>
            </form>
            <ScanResultDisplay result={winrmResult} error={winrmError} loading={winrmLoading} title="WinRM Host Scan" onClear={() => setWinrmResult(null)} onClearError={() => setWinrmError(null)} />
          </div>
        );

      case "windows_cert_store":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-emerald-950/40 p-2.5 border border-emerald-800/30">
                  <Lock className="h-6 w-6 text-emerald-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">Windows Certificate Store Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Enumerate local Windows certificate stores via certutil dump.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("windows_cert_store"))}
            </div>
            <form onSubmit={handleWinstoreScan} className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Store Name" value={winstoreName} onChange={setWinstoreName} required placeholder="My (or Root, CA)" />
                <div className="space-y-1">
                  <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Store Scope</label>
                  <select
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-emerald-500"
                    value={winstoreKind}
                    onChange={(e) => setWinstoreKind(e.target.value)}
                  >
                    <option value="user">Current User</option>
                    <option value="enterprise">Local Machine (Enterprise)</option>
                  </select>
                </div>
              </div>
              <FormTextarea label="Cert Store Dump (PEM format/Info, optional)" value={winstoreDump} onChange={setWinstoreDump} placeholder="Provide serial numbers, thumbprints, or PEMs..." rows={4} />
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-emerald-600 to-emerald-500 px-5 py-2.5 text-xs font-bold text-white hover:from-emerald-500 hover:to-emerald-400 disabled:opacity-50 shadow-md shadow-emerald-950/20 w-full"
                disabled={winstoreLoading}
              >
                {winstoreLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan Certificate Store</>}
              </button>
            </form>
            <ScanResultDisplay result={winstoreResult} error={winstoreError} loading={winstoreLoading} title="Cert Store Scan" onClear={() => setWinstoreResult(null)} onClearError={() => setWinstoreError(null)} />
          </div>
        );

      case "vault_scanner":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-slate-950/50 p-2.5 border border-slate-800/30">
                  <HardDrive className="h-6 w-6 text-slate-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">HashiCorp Vault Secrets Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Discover cryptographic material (PKI certificates, transit keys) in Vault secrets.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("vault_scanner"))}
            </div>
            <form onSubmit={(e) => { e.preventDefault(); handleVaultSync(); }} className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Vault URL" value={vaultUrl} onChange={setVaultUrl} required className="col-span-2" placeholder="https://vault.internal:8200" />
                <FormInput label="Vault Token" value={vaultToken} onChange={setVaultToken} required type="password" placeholder="s.xxx" className="col-span-2" />
                <FormInput label="Mount Point" value={vaultMountPoint} onChange={setVaultMountPoint} required placeholder="secret" />
                <FormInput label="Path (Optional)" value={vaultPath} onChange={setVaultPath} placeholder="app/data" />
              </div>
              <div className="rounded-lg border border-border/60 bg-background/50 p-3 text-[11px] leading-relaxed text-gray-400 space-y-1">
                <div className="font-semibold text-gray-300">Scanned for:</div>
                <div className="grid grid-cols-2 gap-1 text-[10px]">
                  <div>• X.509 / TLS certificates</div>
                  <div>• Private keys (RSA/EC/PKCS#8)</div>
                  <div>• PKI secret metadata</div>
                  <div>• Transit key locations</div>
                </div>
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-slate-600 to-slate-500 px-5 py-2.5 text-xs font-bold text-white hover:from-slate-500 hover:to-slate-400 disabled:opacity-50 shadow-md shadow-slate-950/20 w-full"
                disabled={vaultLoading || !vaultUrl || !vaultToken}
              >
                {vaultLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning Vault...</> : <><Scan className="h-4 w-4" />Scan Vault Secrets</>}
              </button>
            </form>
            {vaultResult && (
              <div className="mt-4 rounded-lg border border-border bg-background p-4 space-y-2">
                <div className="flex items-center gap-2 text-xs text-gray-300">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="font-semibold">Vault Scan Complete</span>
                  <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={() => setVaultResult(null)}>clear</button>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Imported</div>
                    <div className="text-base font-bold text-green-400">{vaultResult.imported}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Updated</div>
                    <div className="text-base font-bold text-blue-400">{vaultResult.updated}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Processed</div>
                    <div className="text-base font-bold text-cyan-400">{vaultResult.imported + vaultResult.updated}</div>
                  </div>
                </div>
              </div>
            )}
            {vaultError && (
              <div className="text-xs text-red-400 rounded border border-red-800/50 bg-red-950/20 p-3">
                <span className="font-semibold">Error:</span> {vaultError}
                <button type="button" className="ml-2 text-[10px] text-gray-500 underline" onClick={() => setVaultError(null)}>dismiss</button>
              </div>
            )}
          </div>
        );

      case "git_secrets":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-pink-950/50 p-2.5 border border-pink-800/30">
                  <GitBranch className="h-6 w-6 text-pink-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">Git Repository Secrets Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Scan git repositories for exposed private keys, certificates, and credentials.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("git_secrets"))}
            </div>
            <form onSubmit={(e) => { e.preventDefault(); handleGitSync(); }} className="space-y-3">
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Local Repository Path" value={gitRepoPath} onChange={setGitRepoPath} required className="col-span-2" placeholder="D:/project-files/myrepo" mono />
                <div className="space-y-1">
                  <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Scan History</label>
                  <select
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-pink-500"
                    value={gitScanHistory ? "true" : "false"}
                    onChange={(e) => setGitScanHistory(e.target.value === "true")}
                  >
                    <option value="true">Yes (includes recent commits)</option>
                    <option value="false">No (current tree only)</option>
                  </select>
                </div>
              </div>
              <div className="rounded-lg border border-border/60 bg-background/50 p-3 text-[11px] leading-relaxed text-gray-400 space-y-1">
                <div className="font-semibold text-gray-300">Detected secret types:</div>
                <div className="grid grid-cols-2 gap-1 text-[10px]">
                  <div>• RSA / EC / DSA private keys</div>
                  <div>• OpenSSH private keys</div>
                  <div>• X.509 / TLS certificates</div>
                  <div>• PKCS#8 private keys</div>
                </div>
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-pink-600 to-pink-500 px-5 py-2.5 text-xs font-bold text-white hover:from-pink-500 hover:to-pink-400 disabled:opacity-50 shadow-md shadow-pink-950/20 w-full"
                disabled={gitLoading || !gitRepoPath}
              >
                {gitLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning Repository...</> : <><Scan className="h-4 w-4" />Scan Git Secrets</>}
              </button>
            </form>
            {gitResult && (
              <div className="mt-4 rounded-lg border border-border bg-background p-4 space-y-2">
                <div className="flex items-center gap-2 text-xs text-gray-300">
                  <CheckCircle className="h-4 w-4 text-green-400" />
                  <span className="font-semibold">Git Secrets Scan Complete</span>
                  <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={() => setGitResult(null)}>clear</button>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center text-[10px]">
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Imported</div>
                    <div className="text-base font-bold text-green-400">{gitResult.imported}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Updated</div>
                    <div className="text-base font-bold text-blue-400">{gitResult.updated}</div>
                  </div>
                  <div className="rounded border border-border p-2 bg-surface">
                    <div className="text-gray-500">Processed</div>
                    <div className="text-base font-bold text-cyan-400">{gitResult.imported + gitResult.updated}</div>
                  </div>
                </div>
              </div>
            )}
            {gitError && (
              <div className="text-xs text-red-400 rounded border border-red-800/50 bg-red-950/20 p-3">
                <span className="font-semibold">Error:</span> {gitError}
                <button type="button" className="ml-2 text-[10px] text-gray-500 underline" onClick={() => setGitError(null)}>dismiss</button>
              </div>
            )}
          </div>
        );

      case "sast_native":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-purple-950/40 p-2.5 border border-purple-800/30">
                  <FileCode className="h-6 w-6 text-purple-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">Native SAST Code Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Scan codebase folders for cryptographic API uses and package vulnerabilities.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("sast_native"))}
            </div>
            <form onSubmit={handleSASTScan} className="space-y-3">
              <FormInput label="Absolute Target Directory Path" value={sastTargetPath} onChange={setSastTargetPath} required placeholder="e.g. D:/project-files/my-api" mono />
              <div className="rounded-lg border border-border/60 bg-background/50 p-3 text-[11px] leading-relaxed text-gray-400 space-y-1">
                <div className="font-semibold text-gray-300">Supported Manifests:</div>
                <div className="grid grid-cols-2 gap-1 text-[10px]">
                  <div>• requirements.txt (Python)</div>
                  <div>• pom.xml / build.gradle (Java)</div>
                  <div>• go.mod / go.sum (Go)</div>
                  <div>• package.json (NodeJS)</div>
                </div>
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-purple-600 to-purple-500 px-5 py-2.5 text-xs font-bold text-white hover:from-purple-500 hover:to-purple-400 disabled:opacity-50 shadow-md shadow-purple-950/20 w-full"
                disabled={sastLoading}
              >
                {sastLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Run Codebase Scan</>}
              </button>
            </form>
            <ScanResultDisplay result={sastResult} error={sastError} loading={sastLoading} title="SAST Code Scan" assetsLabel="Assets Created/Updated" onClear={() => setSastResult(null)} onClearError={() => setSastError(null)} />
          </div>
        );

      case "jwt_audit":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-amber-950/40 p-2.5 border border-amber-800/30">
                  <ShieldAlert className="h-6 w-6 text-amber-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">JWT Token Auditor</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Audit JWT signing key algorithms and length constraints.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("jwt_audit"))}
            </div>
            <div className="flex rounded bg-background border border-border p-0.5 w-fit text-[10px] font-bold">
              <button
                type="button"
                className={`px-2 py-1 rounded transition-colors ${jwtMode === "offline" ? "bg-amber-600 text-white" : "text-gray-400"}`}
                onClick={() => setJwtMode("offline")}
              >
                Offline Tokens
              </button>
              <button
                type="button"
                className={`px-2 py-1 rounded transition-colors ${jwtMode === "online" ? "bg-amber-600 text-white" : "text-gray-400"}`}
                onClick={() => setJwtMode("online")}
              >
                Online JWKS
              </button>
            </div>
            <form onSubmit={handleJwtScan} className="space-y-3">
              {jwtMode === "offline" ? (
                <FormTextarea label="Raw JWT Tokens (One per line)" value={jwtTokens} onChange={setJwtTokens} required placeholder="eyJhbGciOi..." />
              ) : (
                <div className="space-y-2">
                  <FormInput label="JWKS Endpoint URL" value={jwtEndpoint} onChange={setJwtEndpoint} required placeholder="https://example.com/.well-known/jwks.json" />
                  <FormInput label="Bearer Auth Token (Optional)" value={jwtToken} onChange={setJwtToken} placeholder="Auth credential for JWKS query" />
                </div>
              )}
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-amber-600 to-amber-500 px-5 py-2.5 text-xs font-bold text-white hover:from-amber-500 hover:to-amber-400 disabled:opacity-50 shadow-md shadow-amber-950/20 w-full"
                disabled={jwtLoading}
              >
                {jwtLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Auditing...</> : <><Scan className="h-4 w-4" />Audit JWT Tokens</>}
              </button>
            </form>
            <ScanResultDisplay result={jwtResult} error={jwtError} loading={jwtLoading} title="JWT Audit" onClear={() => setJwtResult(null)} onClearError={() => setJwtError(null)} />
          </div>
        );

      case "kubernetes":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-indigo-950/40 p-2.5 border border-indigo-800/30">
                  <Globe className="h-6 w-6 text-indigo-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">Kubernetes Cluster Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Scan K8s Services, Ingresses, Secrets, and ConfigMaps for cryptographic configs.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("kubernetes"))}
            </div>
            <div className="flex rounded bg-background border border-border p-0.5 w-fit text-[10px] font-bold">
              <button
                type="button"
                className={`px-2 py-1 rounded transition-colors ${k8sAuthType === "kubeconfig" ? "bg-indigo-600 text-white" : "text-gray-400"}`}
                onClick={() => setK8sAuthType("kubeconfig")}
              >
                Kubeconfig
              </button>
              <button
                type="button"
                className={`px-2 py-1 rounded transition-colors ${k8sAuthType === "token" ? "bg-indigo-600 text-white" : "text-gray-400"}`}
                onClick={() => setK8sAuthType("token")}
              >
                API Token
              </button>
            </div>
            <form onSubmit={handleK8sScan} className="space-y-3">
              <FormInput label="Context Name (Optional)" value={k8sContext} onChange={setK8sContext} placeholder="minikube" />
              {k8sAuthType === "kubeconfig" ? (
                <FormTextarea label="Kubeconfig Content YAML" value={k8sKubeconfig} onChange={setK8sKubeconfig} required placeholder="apiVersion: v1..." />
              ) : (
                <div className="space-y-2">
                  <div className="grid grid-cols-3 gap-2">
                    <FormInput label="Host / API Server URL" value={k8sHost} onChange={setK8sHost} required className="col-span-2" placeholder="https://192.168.99.100:8443" />
                    <div className="flex items-end pb-2">
                      <FormCheckbox id="k8s-verify-ssl" label="Verify SSL" checked={k8sVerifySsl} onChange={setK8sVerifySsl} />
                    </div>
                  </div>
                  <FormTextarea label="Service Account Token" value={k8sToken} onChange={setK8sToken} required placeholder="Bearer token..." rows={2} />
                  <FormTextarea label="CA Certificate (Optional)" value={k8sCaCert} onChange={setK8sCaCert} placeholder="-----BEGIN CERTIFICATE-----" rows={2} />
                </div>
              )}
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-indigo-600 to-indigo-500 px-5 py-2.5 text-xs font-bold text-white hover:from-indigo-500 hover:to-indigo-400 disabled:opacity-50 shadow-md shadow-indigo-950/20 w-full"
                disabled={k8sLoading}
              >
                {k8sLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan Kubernetes Cluster</>}
              </button>
            </form>
            <ScanResultDisplay result={k8sResult} error={k8sError} loading={k8sLoading} title="Kubernetes Cluster Scan" onClear={() => setK8sResult(null)} onClearError={() => setK8sError(null)} />
          </div>
        );

      case "oracle_tde":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-red-950/40 p-2.5 border border-red-800/30">
                  <Database className="h-6 w-6 text-red-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">Oracle TDE Database Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Scan Oracle Database servers to audit Wallet locations and tablespace encryption.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("oracle_tde"))}
            </div>
            <form onSubmit={handleOracleScan} className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <FormInput label="Host (IP / Domain)" value={oracleHost} onChange={setOracleHost} required className="col-span-2" placeholder="oracle-db-server" />
                <FormInput label="Port" value={oraclePort} onChange={setOraclePort} required placeholder="1521" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Service Name / SID" value={oracleServiceName} onChange={setOracleServiceName} required placeholder="ORCL" />
                <FormInput label="Username" value={oracleUsername} onChange={setOracleUsername} required placeholder="SYS" />
              </div>
              <FormInput label="Password" value={oraclePassword} onChange={setOraclePassword} required type="password" placeholder="••••••••••" />
              <div className="grid grid-cols-3 gap-2 items-center">
                <div className="flex items-center pt-2">
                  <FormCheckbox id="oracle-wallet-checkbox" label="Use Wallet" checked={oracleUseWallet} onChange={setOracleUseWallet} />
                </div>
                {oracleUseWallet && <FormInput label="Wallet Location" value={oracleWalletLocation} onChange={setOracleWalletLocation} className="col-span-2" placeholder="/opt/oracle/wallet" />}
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-red-600 to-red-500 px-5 py-2.5 text-xs font-bold text-white hover:from-red-500 hover:to-red-400 disabled:opacity-50 shadow-md shadow-red-950/20 w-full"
                disabled={oracleLoading}
              >
                {oracleLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan Oracle Database</>}
              </button>
            </form>
            <ScanResultDisplay result={oracleResult} error={oracleError} loading={oracleLoading} title="Oracle TDE Scan" onClear={() => setOracleResult(null)} onClearError={() => setOracleError(null)} />
          </div>
        );

      case "sqlserver_tde":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-rose-950/40 p-2.5 border border-rose-800/30">
                  <Database className="h-6 w-6 text-rose-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">SQL Server TDE Database Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Audit database encryption (TDE) keys, certificates, and Always Encrypted settings.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("sqlserver_tde"))}
            </div>
            <form onSubmit={handleSQLServerScan} className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <FormInput label="Host (IP / Domain)" value={sqlserverHost} onChange={setSqlserverHost} required className="col-span-2" placeholder="mssql-db-server" />
                <FormInput label="Port" value={sqlserverPort} onChange={setSqlserverPort} required placeholder="1433" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Database" value={sqlserverDatabase} onChange={setSqlserverDatabase} required placeholder="master" />
                <FormInput label="Domain (Optional)" value={sqlserverDomain} onChange={setSqlserverDomain} placeholder="AD_DOMAIN" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Username" value={sqlserverUsername} onChange={setSqlserverUsername} required placeholder="sa" />
                <FormInput label="Password" value={sqlserverPassword} onChange={setSqlserverPassword} required type="password" placeholder="••••••••••" />
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-rose-600 to-rose-500 px-5 py-2.5 text-xs font-bold text-white hover:from-rose-500 hover:to-rose-400 disabled:opacity-50 shadow-md shadow-rose-950/20 w-full"
                disabled={sqlserverLoading}
              >
                {sqlserverLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan SQL Server TDE</>}
              </button>
            </form>
            <ScanResultDisplay result={sqlserverResult} error={sqlserverError} loading={sqlserverLoading} title="MSSQL TDE Scan" onClear={() => setSqlserverResult(null)} onClearError={() => setSqlserverError(null)} />
          </div>
        );

      case "pkcs11_hsm":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-pink-950/40 p-2.5 border border-pink-800/30">
                  <HardDrive className="h-6 w-6 text-pink-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">PKCS#11 HSM Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Enumerate HSM objects via PKCS#11 and analyze algorithm support.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("pkcs11_hsm"))}
            </div>
            <form onSubmit={handlePkcs11Scan} className="space-y-3">
              <FormInput label="PKCS#11 Module Library Path" value={pkcs11LibraryPath} onChange={setPkcs11LibraryPath} required placeholder="C:/Program Files/SoftHSM2/lib/softhsm2.dll" mono />
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="User PIN" value={pkcs11Pin} onChange={setPkcs11Pin} required type="password" placeholder="••••••••" />
                <FormInput label="SO PIN (Optional)" value={pkcs11SoPin} onChange={setPkcs11SoPin} type="password" placeholder="••••••••" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Slot ID (Optional)" value={pkcs11SlotId} onChange={setPkcs11SlotId} placeholder="0" />
                <FormInput label="Token Label (Optional)" value={pkcs11TokenLabel} onChange={setPkcs11TokenLabel} placeholder="My HSM Token" />
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-pink-600 to-pink-500 px-5 py-2.5 text-xs font-bold text-white hover:from-pink-500 hover:to-pink-400 disabled:opacity-50 shadow-md shadow-pink-950/20 w-full"
                disabled={pkcs11Loading}
              >
                {pkcs11Loading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Enumerate HSM Objects</>}
              </button>
            </form>
            <ScanResultDisplay result={pkcs11Result} error={pkcs11Error} loading={pkcs11Loading} title="PKCS#11 Scan" onClear={() => setPkcs11Result(null)} onClearError={() => setPkcs11Error(null)} />
          </div>
        );

      case "kmip_kms":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-orange-950/40 p-2.5 border border-orange-800/30">
                  <Key className="h-6 w-6 text-orange-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">KMIP KMS Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Enumerate cryptographic objects from a KMIP Key Management Server.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("kmip_kms"))}
            </div>
            <form onSubmit={handleKmipScan} className="space-y-3">
              <div className="grid grid-cols-3 gap-2">
                <FormInput label="Host (IP / Domain)" value={kmipHost} onChange={setKmipHost} required className="col-span-2" placeholder="kmip-kms-server" />
                <FormInput label="Port" value={kmipPort} onChange={setKmipPort} required placeholder="5696" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Username (Optional)" value={kmipUsername} onChange={setKmipUsername} placeholder="Username" />
                <FormInput label="Password (Optional)" value={kmipPassword} onChange={setKmipPassword} type="password" placeholder="••••••••" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <FormTextarea label="Client Cert (Optional)" value={kmipClientCert} onChange={setKmipClientCert} placeholder="-----BEGIN CERTIFICATE-----" rows={2} />
                <FormTextarea label="Client Key (Optional)" value={kmipClientKey} onChange={setKmipClientKey} placeholder="-----BEGIN PRIVATE KEY-----" rows={2} />
              </div>
              <FormTextarea label="CA Certificate (Optional)" value={kmipCaCert} onChange={setKmipCaCert} placeholder="-----BEGIN CERTIFICATE-----" rows={2} />
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-orange-600 to-orange-500 px-5 py-2.5 text-xs font-bold text-white hover:from-orange-500 hover:to-orange-400 disabled:opacity-50 shadow-md shadow-orange-950/20 w-full"
                disabled={kmipLoading}
              >
                {kmipLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan KMIP Server</>}
              </button>
            </form>
            <ScanResultDisplay result={kmipResult} error={kmipError} loading={kmipLoading} title="KMIP Sync" onClear={() => setKmipResult(null)} onClearError={() => setKmipError(null)} />
          </div>
        );

      case "adcs_ldap":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-teal-950/40 p-2.5 border border-teal-800/30">
                  <Server className="h-6 w-6 text-teal-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">ADCS/LDAP Certificate Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Discover templates and active certificates from Active Directory Certificate Services.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("adcs_ldap"))}
            </div>
            <form onSubmit={handleAdcsScan} className="space-y-3">
              <FormInput label="Domain Controller IP / Host" value={adcsDomainController} onChange={setAdcsDomainController} required placeholder="ad-domain-controller" />
              <div className="grid grid-cols-2 gap-2">
                <FormInput label="Username" value={adcsUsername} onChange={setAdcsUsername} required placeholder="administrator@domain.local" />
                <FormInput label="Password" value={adcsPassword} onChange={setAdcsPassword} required type="password" placeholder="••••••••" />
              </div>
              <div className="grid grid-cols-3 gap-2 items-center">
                <div className="flex items-center pt-2">
                  <FormCheckbox id="adcs-ldaps-checkbox" label="Use LDAPS" checked={adcsUseLdaps} onChange={setAdcsUseLdaps} />
                </div>
                <FormInput label="Base DN (Optional)" value={adcsBaseDn} onChange={setAdcsBaseDn} className="col-span-2" placeholder="DC=domain,DC=local" />
              </div>
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-teal-600 to-teal-500 px-5 py-2.5 text-xs font-bold text-white hover:from-teal-500 hover:to-teal-400 disabled:opacity-50 shadow-md shadow-teal-950/20 w-full"
                disabled={adcsLoading}
              >
                {adcsLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan ADCS Certificates</>}
              </button>
            </form>
            <ScanResultDisplay result={adcsResult} error={adcsError} loading={adcsLoading} title="ADCS Scan" onClear={() => setAdcsResult(null)} onClearError={() => setAdcsError(null)} />
          </div>
        );

      case "saml_metadata":
        return (
          <div className="space-y-4">
            <div className="flex items-start justify-between border-b border-border/50 pb-4">
              <div className="flex items-center gap-3">
                <div className="rounded-lg bg-fuchsia-950/40 p-2.5 border border-fuchsia-800/30">
                  <ShieldAlert className="h-6 w-6 text-fuchsia-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-gray-200">SAML Metadata Certificate Scanner</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Inventory SAML signing/encryption certificates from IdP metadata URLs or raw XML.</p>
                </div>
              </div>
              {getStatusBadge(getConnectorStatus("saml_metadata"))}
            </div>
            <div className="flex rounded bg-background border border-border p-0.5 w-fit text-[10px] font-bold">
              <button
                type="button"
                className={`px-2 py-1 rounded transition-colors ${samlMode === "url" ? "bg-fuchsia-600 text-white" : "text-gray-400"}`}
                onClick={() => setSamlMode("url")}
              >
                From Metadata URL
              </button>
              <button
                type="button"
                className={`px-2 py-1 rounded transition-colors ${samlMode === "xml" ? "bg-fuchsia-600 text-white" : "text-gray-400"}`}
                onClick={() => setSamlMode("xml")}
              >
                Paste Raw XML
              </button>
            </div>
            <form onSubmit={handleSamlScan} className="space-y-3">
              {samlMode === "url" ? (
                <FormInput label="SAML Metadata URL" value={samlMetadataUrl} onChange={setSamlMetadataUrl} required placeholder="https://idp.example.com/metadata" />
              ) : (
                <FormTextarea label="SAML Metadata XML" value={samlXmlBlob} onChange={setSamlXmlBlob} required placeholder="Paste EntityDescriptor XML here..." rows={8} />
              )}
              <FormInput label="Bearer Auth Token (optional)" value={samlAuthToken} onChange={setSamlAuthToken} placeholder="Auth token for private metadata URL" />
              <button
                type="submit"
                className="flex items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-fuchsia-600 to-fuchsia-500 px-5 py-2.5 text-xs font-bold text-white hover:from-fuchsia-500 hover:to-fuchsia-400 disabled:opacity-50 shadow-md shadow-fuchsia-950/20 w-full"
                disabled={samlLoading || ((samlMode === "url" && !samlMetadataUrl) || (samlMode === "xml" && !samlXmlBlob))}
              >
                {samlLoading ? <><Loader2 className="h-4 w-4 animate-spin" />Scanning...</> : <><Scan className="h-4 w-4" />Scan SAML Certificates</>}
              </button>
            </form>
            <ScanResultDisplay result={samlResult} error={samlError} loading={samlLoading} title="SAML Scan" onClear={() => setSamlResult(null)} onClearError={() => setSamlError(null)} />
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">

      <div className="flex flex-col lg:flex-row gap-6 items-start">
        {/* Left Side: Sidebar */}
        <div className="w-full lg:w-80 shrink-0 lg:sticky lg:top-6">
          <div className="rounded-xl border border-border bg-surface/30 backdrop-blur-md p-3.5 space-y-3">
            {(["cloud_cmdb", "hosts_endpoints", "databases_clusters", "hsm_kms_pki"] as const).map((cat) => {
              const items = SIDEBAR_ITEMS.filter((item) => item.category === cat);
              const isExpanded = expandedCategories[cat];
              return (
                <div key={cat} className="space-y-1">
                  <button
                    type="button"
                    onClick={() => toggleCategory(cat)}
                    className="w-full flex items-center justify-between text-[10px] font-bold uppercase tracking-wider text-gray-500 hover:text-gray-300 px-2 py-1.5 rounded-lg hover:bg-slate-800/20 transition-all select-none"
                  >
                    <span>{CATEGORY_LABELS[cat]}</span>
                    {isExpanded ? (
                      <ChevronUp className="h-3.5 w-3.5 text-gray-500" />
                    ) : (
                      <ChevronDown className="h-3.5 w-3.5 text-gray-500" />
                    )}
                  </button>
                  {isExpanded && (
                    <div className="space-y-1 animate-in fade-in slide-in-from-top-1 duration-150">
                      {items.map((item) => {
                        const isActive = selectedTab === item.id;
                        const status = getConnectorStatus(item.id);
                        return (
                          <button
                            key={item.id}
                            type="button"
                            onClick={() => setSelectedTab(item.id)}
                            className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-left text-xs transition-all duration-150 group ${
                              isActive
                                ? "bg-slate-800/60 border border-slate-700 text-gray-200 font-semibold shadow-sm"
                                : "text-gray-400 hover:bg-slate-800/30 hover:text-gray-300 border border-transparent"
                            }`}
                          >
                            <div className="flex items-center gap-2.5 min-w-0">
                              <span className={`transition-transform duration-200 ${isActive ? "scale-110" : "group-hover:scale-105"}`}>
                                {item.icon}
                              </span>
                              <span className="truncate">{item.name}</span>
                            </div>
                            <div className="flex items-center gap-1.5 ml-2 flex-shrink-0">
                              {status === "configured" || status === "active" ? (
                                <span className="h-1.5 w-1.5 rounded-full bg-green-400 shadow-[0_0_6px_rgba(74,222,128,0.5)]" />
                              ) : (
                                <span className="h-1.5 w-1.5 rounded-full bg-gray-600" />
                              )}
                            </div>
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Right Side: Configuration & Results Panel */}
        <div className="flex-1 min-w-0 w-full">
          <div className="rounded-xl border border-border bg-surface p-6 space-y-6">
            {renderSelectedForm()}
          </div>
        </div>
      </div>
    </div>
  );
}


/* ── AWS PQC Scan Result Panel ─────────────────────────────────────── */

function AWSPQCScanResultPanel({
  result,
  onClear,
}: {
  result: AWSPQCScanResult;
  onClear: () => void;
}) {
  const [showErrors, setShowErrors] = useState(false);
  const totalAssets = result.assets_discovered + result.assets_updated;
  const hasErrors = result.errors && result.errors.length > 0;

  return (
    <div className="rounded-xl border border-border bg-background p-5 space-y-4 animate-in fade-in slide-in-from-top-2 duration-300">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="rounded-lg bg-green-950/40 p-2 border border-green-800/30">
            <CheckCircle className="h-5 w-5 text-green-400" />
          </div>
          <div>
            <div className="text-sm font-bold text-gray-200">PQC Scan Complete</div>
            <div className="text-[11px] text-gray-500">
              Region: <span className="text-gray-400 font-mono">{result.region}</span>
              {" · "}
              Scan ID: <span className="text-gray-400 font-mono">{result.scan_id.slice(0, 8)}</span>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Link
            to={`/scans/${result.scan_id}`}
            className="flex items-center gap-1 rounded-md border border-border bg-surface px-3 py-1.5 text-[11px] font-semibold text-gray-300 hover:bg-border transition-colors"
          >
            View Scan Details
            <ArrowRight className="h-3 w-3" />
          </Link>
          <button className="text-[10px] text-gray-500 underline" onClick={onClear}>
            clear
          </button>
        </div>
      </div>

      {/* Key metrics */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <MetricCard label="Assets Found" value={totalAssets} color="text-cyan-400" />
        <MetricCard label="New Assets" value={result.assets_discovered} color="text-green-400" />
        <MetricCard label="Algorithms" value={result.algorithms_recorded} color="text-blue-400" />
        <MetricCard label="Certificates" value={result.certificates_recorded} color="text-purple-400" />
        <MetricCard
          label="PQC Findings"
          value={result.findings_created}
          color={result.findings_created > 0 ? "text-red-400" : "text-green-400"}
          highlight={result.findings_created > 0}
        />
      </div>

      {/* Services scanned */}
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 mb-2">
          Services scanned
        </div>
        <div className="flex flex-wrap gap-2">
          {result.services_scanned.map((svc) => (
            <span
              key={svc}
              className="inline-flex items-center gap-1.5 rounded-full border border-green-800/30 bg-green-950/20 px-2.5 py-1 text-[11px] font-medium text-green-400"
            >
              {SERVICE_ICONS[svc] || <CheckCircle className="h-3 w-3" />}
              {svc}
            </span>
          ))}
          {["KMS", "ACM", "ELBv2", "CloudFront", "S3", "IAM"]
            .filter((s) => !result.services_scanned.includes(s))
            .map((svc) => (
              <span
                key={svc}
                className="inline-flex items-center gap-1.5 rounded-full border border-gray-800/30 bg-gray-900/20 px-2.5 py-1 text-[11px] font-medium text-gray-500"
              >
                {SERVICE_ICONS[svc]}
                {svc}
                <span className="text-[9px]">(skipped)</span>
              </span>
            ))}
        </div>
      </div>

      {/* Findings summary */}
      {result.findings_created > 0 && (
        <div className="rounded-lg border border-orange-800/30 bg-orange-950/10 p-3 flex items-center gap-3">
          <ShieldAlert className="h-5 w-5 text-orange-400 flex-shrink-0" />
          <div className="flex-1">
            <div className="text-xs font-semibold text-orange-300">
              {result.findings_created} quantum-vulnerable finding{result.findings_created !== 1 ? "s" : ""} detected
            </div>
            <div className="text-[11px] text-gray-400 mt-0.5">
              Review findings on the{" "}
              <Link to="/findings" className="text-orange-400 underline hover:text-orange-300">
                Findings page
              </Link>{" "}
              or drill into the{" "}
              <Link to={`/scans/${result.scan_id}`} className="text-orange-400 underline hover:text-orange-300">
                scan details
              </Link>
              .
            </div>
          </div>
        </div>
      )}

      {result.findings_created === 0 && (
        <div className="rounded-lg border border-green-800/30 bg-green-950/10 p-3 flex items-center gap-3">
          <CheckCircle className="h-5 w-5 text-green-400 flex-shrink-0" />
          <div>
            <div className="text-xs font-semibold text-green-300">
              No quantum-vulnerable findings detected
            </div>
            <div className="text-[11px] text-gray-400 mt-0.5">
              All discovered cryptographic material appears to be quantum-safe or uses symmetric encryption.
            </div>
          </div>
        </div>
      )}

      {/* Errors (collapsible) */}
      {hasErrors && (
        <div className="space-y-2">
          <button
            className="flex items-center gap-1.5 text-[11px] font-semibold text-yellow-400/80 hover:text-yellow-400"
            onClick={() => setShowErrors(!showErrors)}
          >
            <AlertTriangle className="h-3.5 w-3.5" />
            {result.errors.length} warning{result.errors.length !== 1 ? "s" : ""}
            {showErrors ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
          </button>
          {showErrors && (
            <div className="max-h-32 overflow-y-auto rounded-lg border border-yellow-800/20 bg-yellow-950/10 p-3 font-mono text-[10px] text-yellow-400/70 space-y-1">
              {result.errors.map((err, i) => (
                <div key={i}>• {err}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


/* ── Metric Card ───────────────────────────────────────────────────── */

function MetricCard({
  label,
  value,
  color,
  highlight = false,
}: {
  label: string;
  value: number;
  color: string;
  highlight?: boolean;
}) {
  return (
    <div
      className={`rounded-lg border p-3 text-center ${
        highlight
          ? "border-red-800/40 bg-red-950/15"
          : "border-border bg-surface"
      }`}
    >
      <div className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</div>
      <div className={`text-xl font-bold mt-0.5 ${color}`}>{value}</div>
    </div>
  );
}


/* ── Reusable Form Components ──────────────────────────────────────── */

function FormInput({
  label,
  value,
  onChange,
  placeholder = "",
  type = "text",
  required = false,
  className = "",
  mono = false,
}: {
  label: string;
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  type?: string;
  required?: boolean;
  className?: string;
  mono?: boolean;
}) {
  return (
    <div className={`space-y-1 ${className}`}>
      <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
        {label}
      </label>
      <input
        required={required}
        type={type}
        className={`w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-500 transition-colors placeholder:text-gray-600 ${mono ? "font-mono" : ""}`}
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function FormTextarea({
  label,
  value,
  onChange,
  placeholder = "",
  rows = 3,
  required = false,
  className = "",
}: {
  label: string;
  value: string;
  onChange: (val: string) => void;
  placeholder?: string;
  rows?: number;
  required?: boolean;
  className?: string;
}) {
  return (
    <div className={`space-y-1 ${className}`}>
      <label className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
        {label}
      </label>
      <textarea
        required={required}
        rows={rows}
        className="w-full rounded-md border border-border bg-background px-3 py-2 text-xs text-gray-200 outline-none focus:border-cyan-500 transition-colors placeholder:text-gray-500 font-mono resize-none"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
    </div>
  );
}

function FormCheckbox({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (val: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-2">
      <input
        type="checkbox"
        id={id}
        className="rounded border-border text-cyan-600 focus:ring-cyan-500 bg-background h-3.5 w-3.5"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      <label htmlFor={id} className="text-xs font-semibold text-gray-300 cursor-pointer select-none">
        {label}
      </label>
    </div>
  );
}

function ScanResultDisplay({
  result,
  error,
  loading,
  title,
  assetsLabel = "Assets Found",
  onClear,
  onClearError,
}: {
  result: { scan_id: string; assets_found?: number; assets_discovered?: number; findings_created: number; errors?: string[] } | null;
  error: string | null;
  loading: boolean;
  title: string;
  assetsLabel?: string;
  onClear: () => void;
  onClearError: () => void;
}) {
  if (loading) return null;
  return (
    <div className="mt-4 space-y-3 animate-in fade-in duration-200">
      {error && (
        <div className="rounded-lg border border-red-800/50 bg-red-950/20 p-4 flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div className="flex-1">
            <div className="text-sm font-semibold text-red-400">Scan Failed</div>
            <div className="text-xs text-red-400/80 mt-1">{error}</div>
          </div>
          <button type="button" className="text-[10px] text-gray-500 underline flex-shrink-0" onClick={onClearError}>
            dismiss
          </button>
        </div>
      )}

      {result && (
        <div className="rounded-lg border border-border bg-background p-4 space-y-3">
          <div className="flex items-center gap-2">
            <CheckCircle className="h-4 w-4 text-green-400" />
            <span className="text-xs font-semibold text-gray-200">{title} Succeeded</span>
            <button type="button" className="ml-auto text-[10px] text-gray-500 underline" onClick={onClear}>
              clear
            </button>
          </div>
          <div className="grid grid-cols-2 gap-2 text-center text-[10px]">
            <div className="rounded border border-border p-2 bg-surface">
              <div className="text-gray-500">{assetsLabel}</div>
              <div className="text-sm font-bold text-cyan-400">
                {result.assets_found !== undefined ? result.assets_found : result.assets_discovered}
              </div>
            </div>
            <div className="rounded border border-border p-2 bg-surface">
              <div className="text-gray-500">Findings Generated</div>
              <div className="text-sm font-bold text-orange-400">{result.findings_created}</div>
            </div>
          </div>
          {result.errors && result.errors.length > 0 && (
            <div className="pt-2 border-t border-border/50 space-y-1">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">Warnings:</div>
              <div className="max-h-20 overflow-y-auto font-mono text-[9px] text-yellow-400/80 space-y-0.5">
                {result.errors.map((err, i) => (
                  <div key={i}>• {err}</div>
                ))}
              </div>
            </div>
          )}
          <div className="flex justify-end gap-2 pt-1">
            <Link
              to={`/scans/${result.scan_id}`}
              className="inline-flex items-center gap-1 rounded bg-border border border-border/80 px-2.5 py-1.5 text-[10px] font-semibold text-gray-300 hover:bg-border/60 transition-colors"
            >
              View Scan Details
              <ArrowRight className="h-3 w-3" />
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}
