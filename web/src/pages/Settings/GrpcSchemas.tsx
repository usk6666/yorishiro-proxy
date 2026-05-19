import { useCallback, useRef, useState } from "react";
import {
  Badge,
  Button,
  Input,
  Spinner,
  useDialog,
  useToast,
} from "../../components/ui/index.js";
import {
  useGrpcSchema,
  useGrpcSchemaList,
} from "../../lib/mcp/hooks.js";
import type {
  GrpcSchemaClearResult,
  GrpcSchemaRegisterResult,
  GrpcSchemaServiceEntry,
  GrpcSchemaUnregisterResult,
} from "../../lib/mcp/types.js";

/**
 * Maximum decoded descriptor_set size accepted by the proxy server,
 * mirrored client-side as a preflight check (USK-927 design review #5).
 * Server-side cap lives at
 * `internal/encoding/protoschema/registry.go:MaxDescriptorSetBytes`.
 */
const MAX_DESCRIPTOR_BYTES = 16 * 1024 * 1024;

/** Chunk size used during base64 encoding to avoid stack overflow. */
const BASE64_CHUNK_SIZE = 0x8000; // 32 KiB

/**
 * Convert a Uint8Array to a base64 string in chunks. Large
 * `String.fromCharCode.apply()` calls overflow the JS argument-stack limit
 * around a few hundred KiB; chunking keeps each apply() call below the
 * 32 KiB threshold so files up to the 16 MiB cap encode safely.
 */
function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += BASE64_CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + BASE64_CHUNK_SIZE);
    binary += String.fromCharCode.apply(
      null,
      chunk as unknown as number[],
    );
  }
  return btoa(binary);
}

/**
 * Split a textarea's value into a trimmed, non-empty string list (one
 * entry per line). Used for service_filter, proto_paths, import_paths.
 */
function splitLines(value: string): string[] {
  return value
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

/** Render the methods column for a single service row. */
function MethodsList({ methods }: { methods: GrpcSchemaServiceEntry["methods"] }) {
  if (!methods || methods.length === 0) {
    return <span className="settings-rule-detail">No methods</span>;
  }
  const renderText = methods
    .map((m) => `${m.name}(${m.input}) → ${m.output}`)
    .join(", ");
  // Collapse beyond 5 methods to keep the row scan-friendly.
  if (methods.length > 5) {
    return (
      <details>
        <summary
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-xs)",
            color: "var(--text-secondary)",
            cursor: "pointer",
          }}
        >
          {methods.length} methods (expand)
        </summary>
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: "var(--font-size-xs)",
            color: "var(--text-secondary)",
            wordBreak: "break-all",
          }}
        >
          {renderText}
        </span>
      </details>
    );
  }
  return (
    <span
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "var(--font-size-xs)",
        color: "var(--text-secondary)",
        wordBreak: "break-all",
      }}
    >
      {renderText}
    </span>
  );
}

/**
 * GrpcSchemas — operator-facing management panel for the `grpc_schema`
 * MCP tool (USK-923 / USK-926 / USK-927).
 *
 * Surfaces:
 *   - List of registered services with method signatures, source label,
 *     and registered timestamp.
 *   - Per-row Unregister button (confirm dialog).
 *   - Clear-all action (confirm dialog).
 *   - Descriptor_set upload form (.desc → base64, 16 MiB preflight).
 *   - Collapsed disclosure for source="file" (proto_paths + import_paths).
 *
 * Discovery (USK-928 reflection) is intentionally out of scope; tracked
 * by a follow-up Issue per USK-927 design review D1.
 */
export function GrpcSchemas() {
  const { addToast } = useToast();
  const { showDialog } = useDialog();
  const { data, loading: listLoading, error: listError, refetch } =
    useGrpcSchemaList();
  const { grpcSchema, loading: actionLoading } = useGrpcSchema();

  // Upload (descriptor_set) form state.
  const [showUploadForm, setShowUploadForm] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [serviceFilterText, setServiceFilterText] = useState("");
  const [sourceLabel, setSourceLabel] = useState("");
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  // File-mode (source="file") form state.
  const [protoPathsText, setProtoPathsText] = useState("");
  const [importPathsText, setImportPathsText] = useState("");
  const [fileModeServiceFilter, setFileModeServiceFilter] = useState("");
  const [fileModeSourceLabel, setFileModeSourceLabel] = useState("");

  const schemas = data?.schemas ?? [];

  const handleFileChange = useCallback(
    (event: React.ChangeEvent<HTMLInputElement>) => {
      const file = event.target.files?.[0] ?? null;
      if (file && file.size > MAX_DESCRIPTOR_BYTES) {
        addToast({
          type: "error",
          message: `File exceeds 16 MiB limit (${(file.size / 1024 / 1024).toFixed(2)} MiB)`,
        });
        if (fileInputRef.current) {
          fileInputRef.current.value = "";
        }
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      // Default the source label to the file name so the operator can
      // see/edit before submit (design review #7).
      if (file && !sourceLabel.trim()) {
        setSourceLabel(file.name);
      }
    },
    [addToast, sourceLabel],
  );

  const resetUploadForm = useCallback(() => {
    setSelectedFile(null);
    setServiceFilterText("");
    setSourceLabel("");
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
  }, []);

  const handleUpload = useCallback(async () => {
    if (!selectedFile) {
      addToast({ type: "warning", message: "Select a .desc file to upload" });
      return;
    }
    if (selectedFile.size > MAX_DESCRIPTOR_BYTES) {
      addToast({
        type: "error",
        message: `File exceeds 16 MiB limit (${(selectedFile.size / 1024 / 1024).toFixed(2)} MiB)`,
      });
      return;
    }
    try {
      const buf = await selectedFile.arrayBuffer();
      const bytes = new Uint8Array(buf);
      const b64 = bytesToBase64(bytes);
      const serviceFilter = splitLines(serviceFilterText);
      const result = await grpcSchema<GrpcSchemaRegisterResult>({
        action: "register",
        params: {
          source: "descriptor_set",
          descriptor_set_b64: b64,
          ...(serviceFilter.length > 0 ? { service_filter: serviceFilter } : {}),
          ...(sourceLabel.trim() ? { source_label: sourceLabel.trim() } : {}),
        },
      });
      const count = result.registered?.length ?? 0;
      addToast({
        type: "success",
        message: `Registered ${count} service${count === 1 ? "" : "s"} from "${selectedFile.name}"`,
      });
      resetUploadForm();
      setShowUploadForm(false);
      await refetch();
    } catch (err) {
      addToast({
        type: "error",
        message: `Upload failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [
    selectedFile,
    serviceFilterText,
    sourceLabel,
    grpcSchema,
    addToast,
    refetch,
    resetUploadForm,
  ]);

  const handleFileModeRegister = useCallback(async () => {
    const protoPaths = splitLines(protoPathsText);
    if (protoPaths.length === 0) {
      addToast({
        type: "warning",
        message: "Add at least one absolute .proto file path",
      });
      return;
    }
    const importPaths = splitLines(importPathsText);
    const serviceFilter = splitLines(fileModeServiceFilter);
    try {
      const result = await grpcSchema<GrpcSchemaRegisterResult>({
        action: "register",
        params: {
          source: "file",
          proto_paths: protoPaths,
          ...(importPaths.length > 0 ? { import_paths: importPaths } : {}),
          ...(serviceFilter.length > 0 ? { service_filter: serviceFilter } : {}),
          ...(fileModeSourceLabel.trim()
            ? { source_label: fileModeSourceLabel.trim() }
            : {}),
        },
      });
      const count = result.registered?.length ?? 0;
      addToast({
        type: "success",
        message: `Registered ${count} service${count === 1 ? "" : "s"} via protoc`,
      });
      setProtoPathsText("");
      setImportPathsText("");
      setFileModeServiceFilter("");
      setFileModeSourceLabel("");
      await refetch();
    } catch (err) {
      addToast({
        type: "error",
        message: `protoc register failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [
    protoPathsText,
    importPathsText,
    fileModeServiceFilter,
    fileModeSourceLabel,
    grpcSchema,
    addToast,
    refetch,
  ]);

  const handleUnregister = useCallback(
    async (service: string) => {
      const confirmed = await showDialog({
        title: "Unregister schema",
        message: `Unregister service ${service}?`,
        variant: "confirm",
        confirmLabel: "Unregister",
        confirmVariant: "danger",
      });
      if (!confirmed) return;
      try {
        const result = await grpcSchema<GrpcSchemaUnregisterResult>({
          action: "unregister",
          params: { service },
        });
        if (result.unregistered) {
          addToast({ type: "success", message: `Unregistered ${service}` });
        } else {
          addToast({
            type: "warning",
            message: `Service ${service} was not registered`,
          });
        }
        await refetch();
      } catch (err) {
        addToast({
          type: "error",
          message: `Unregister failed: ${err instanceof Error ? err.message : String(err)}`,
        });
      }
    },
    [grpcSchema, addToast, refetch, showDialog],
  );

  const handleClearAll = useCallback(async () => {
    const count = schemas.length;
    if (count === 0) return;
    const confirmed = await showDialog({
      title: "Clear all gRPC schemas",
      message: `All ${count} registered schema${count === 1 ? "" : "s"} will be removed. Continue?`,
      variant: "confirm",
      confirmLabel: "Clear all",
      confirmVariant: "danger",
    });
    if (!confirmed) return;
    try {
      const result = await grpcSchema<GrpcSchemaClearResult>({
        action: "clear",
      });
      addToast({
        type: "success",
        message: `Cleared ${result.cleared} schema${result.cleared === 1 ? "" : "s"}`,
      });
      await refetch();
    } catch (err) {
      addToast({
        type: "error",
        message: `Clear failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }, [schemas.length, grpcSchema, addToast, refetch, showDialog]);

  return (
    <div className="settings-section">
      {/* Schema list section */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">
            Registered gRPC Schemas ({schemas.length})
          </span>
          <div className="settings-card-actions">
            <Button
              variant="primary"
              size="sm"
              onClick={() => setShowUploadForm(!showUploadForm)}
            >
              {showUploadForm ? "Cancel" : "Upload .desc"}
            </Button>
            <Button
              variant="danger"
              size="sm"
              onClick={handleClearAll}
              disabled={schemas.length === 0 || actionLoading}
            >
              Clear all
            </Button>
          </div>
        </div>
        <div className="settings-card-body">
          <p className="settings-section-desc">
            Registered .proto schemas drive schema-aware decode in <code>query messages</code>
            {" "}(<code>body_decoded_encoding=&quot;proto-json&quot;</code>) and accept{" "}
            <code>body_encoding=&quot;proto-json&quot;</code> on <code>resend_grpc</code>.
            Schemaless fallback applies when no schema matches a flow.
          </p>

          {/* Upload form (descriptor_set source) */}
          {showUploadForm && (
            <div
              className="settings-add-form"
              style={{ marginBottom: "var(--space-md)" }}
            >
              <div className="settings-add-form-title">
                Upload FileDescriptorSet (.desc)
              </div>
              <p className="settings-section-desc">
                Generate the descriptor with{" "}
                <code>protoc --include_imports --descriptor_set_out=out.desc *.proto</code>
                {" "}on your operator machine, then upload the resulting{" "}
                <code>.desc</code> file here (max 16 MiB).
              </p>
              <div className="settings-form-row">
                <div className="input-wrapper">
                  <label
                    className="input-label"
                    htmlFor="grpc-schema-file-input"
                  >
                    Descriptor file
                  </label>
                  <input
                    ref={fileInputRef}
                    id="grpc-schema-file-input"
                    type="file"
                    accept=".desc,.pb,.bin,application/octet-stream"
                    onChange={handleFileChange}
                    aria-describedby="grpc-schema-file-hint"
                  />
                  <span
                    id="grpc-schema-file-hint"
                    className="settings-rule-detail"
                  >
                    .desc / .pb / .bin (FileDescriptorSet); max 16 MiB
                  </span>
                </div>
              </div>
              <div className="settings-form-row">
                <Input
                  label="Source label (optional)"
                  value={sourceLabel}
                  onChange={(e) => setSourceLabel(e.target.value)}
                  placeholder="Defaults to the file name"
                />
              </div>
              <div className="settings-form-row">
                <div className="input-wrapper" style={{ flex: 1 }}>
                  <label
                    className="input-label"
                    htmlFor="grpc-schema-service-filter"
                  >
                    Service filter (optional, one per line)
                  </label>
                  <textarea
                    id="grpc-schema-service-filter"
                    className="input"
                    value={serviceFilterText}
                    onChange={(e) => setServiceFilterText(e.target.value)}
                    placeholder={"pkg.Service1\npkg.Service2"}
                    rows={3}
                    style={{
                      fontFamily: "var(--font-mono)",
                      resize: "vertical",
                      minHeight: "60px",
                    }}
                  />
                  <span className="settings-rule-detail">
                    Fully-qualified service names. Leave blank to register every service in the descriptor.
                  </span>
                </div>
              </div>
              <div className="settings-add-form-actions">
                <Button
                  variant="secondary"
                  size="sm"
                  onClick={() => {
                    resetUploadForm();
                    setShowUploadForm(false);
                  }}
                  disabled={actionLoading}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleUpload}
                  disabled={!selectedFile || actionLoading}
                >
                  {actionLoading ? "Uploading..." : "Register"}
                </Button>
              </div>
            </div>
          )}

          {/* Schema list */}
          {listLoading && !data ? (
            <div className="settings-loading">
              <Spinner size="md" />
            </div>
          ) : listError ? (
            <div className="settings-error">
              Error loading schemas: {listError.message}
            </div>
          ) : schemas.length === 0 ? (
            <div className="settings-empty">
              No gRPC schemas registered
            </div>
          ) : (
            <div className="settings-item-list">
              {schemas.map((schema) => (
                <div key={schema.service} className="settings-rule">
                  <div className="settings-rule-info">
                    <span className="settings-rule-id">{schema.service}</span>
                    <MethodsList methods={schema.methods} />
                    <div
                      style={{
                        display: "flex",
                        gap: "var(--space-xs)",
                        marginTop: "var(--space-xs)",
                        flexWrap: "wrap",
                      }}
                    >
                      {schema.source_label && (
                        <Badge variant="info">{schema.source_label}</Badge>
                      )}
                      {schema.registered_at && (
                        <span className="settings-rule-detail">
                          Registered: {schema.registered_at}
                        </span>
                      )}
                    </div>
                  </div>
                  <div className="settings-rule-actions">
                    <Button
                      variant="danger"
                      size="sm"
                      onClick={() => handleUnregister(schema.service)}
                      disabled={actionLoading}
                    >
                      Unregister
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* File-mode (source="file") disclosure */}
      <div className="settings-card">
        <div className="settings-card-header">
          <span className="settings-card-title">Advanced</span>
        </div>
        <div className="settings-card-body">
          <details>
            <summary
              style={{
                cursor: "pointer",
                color: "var(--text-secondary)",
                fontSize: "var(--font-size-sm)",
                marginBottom: "var(--space-sm)",
              }}
            >
              Compile from .proto files (advanced)
            </summary>
            <p className="settings-section-desc">
              The proxy invokes its host <code>protoc</code> binary against
              the listed absolute paths. Paths must be canonical and fall
              under the proxy CWD or one of the import paths. Operation has
              a 30 s timeout (server-enforced).
            </p>
            <div className="settings-form-row">
              <div className="input-wrapper" style={{ flex: 1 }}>
                <label
                  className="input-label"
                  htmlFor="grpc-schema-proto-paths"
                >
                  Proto paths (one absolute path per line)
                </label>
                <textarea
                  id="grpc-schema-proto-paths"
                  className="input"
                  value={protoPathsText}
                  onChange={(e) => setProtoPathsText(e.target.value)}
                  placeholder={"/absolute/path/to/foo.proto\n/absolute/path/to/bar.proto"}
                  rows={3}
                  style={{
                    fontFamily: "var(--font-mono)",
                    resize: "vertical",
                    minHeight: "60px",
                  }}
                />
              </div>
            </div>
            <div className="settings-form-row">
              <div className="input-wrapper" style={{ flex: 1 }}>
                <label
                  className="input-label"
                  htmlFor="grpc-schema-import-paths"
                >
                  Import paths (optional, one per line)
                </label>
                <textarea
                  id="grpc-schema-import-paths"
                  className="input"
                  value={importPathsText}
                  onChange={(e) => setImportPathsText(e.target.value)}
                  placeholder={"/absolute/path/to/protoroot1\n/absolute/path/to/protoroot2"}
                  rows={2}
                  style={{
                    fontFamily: "var(--font-mono)",
                    resize: "vertical",
                    minHeight: "40px",
                  }}
                />
                <span className="settings-rule-detail">
                  Passed to <code>protoc -I&lt;root&gt;</code>. Defaults to each proto path&apos;s parent directory.
                </span>
              </div>
            </div>
            <div className="settings-form-row">
              <Input
                label="Source label (optional)"
                value={fileModeSourceLabel}
                onChange={(e) => setFileModeSourceLabel(e.target.value)}
                placeholder="Defaults to comma-joined basenames"
              />
            </div>
            <div className="settings-form-row">
              <div className="input-wrapper" style={{ flex: 1 }}>
                <label
                  className="input-label"
                  htmlFor="grpc-schema-file-service-filter"
                >
                  Service filter (optional, one per line)
                </label>
                <textarea
                  id="grpc-schema-file-service-filter"
                  className="input"
                  value={fileModeServiceFilter}
                  onChange={(e) => setFileModeServiceFilter(e.target.value)}
                  placeholder={"pkg.Service1\npkg.Service2"}
                  rows={2}
                  style={{
                    fontFamily: "var(--font-mono)",
                    resize: "vertical",
                    minHeight: "40px",
                  }}
                />
              </div>
            </div>
            <div className="settings-add-form-actions">
              <Button
                variant="primary"
                size="sm"
                onClick={handleFileModeRegister}
                disabled={actionLoading || protoPathsText.trim().length === 0}
              >
                {actionLoading ? "Compiling..." : "Compile and register"}
              </Button>
            </div>
          </details>
        </div>
      </div>
    </div>
  );
}
