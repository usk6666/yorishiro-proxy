# docs

Self-service documentation for this MCP server. Every help document that ships with yorishiro-proxy is reachable through this one tool, so an agent never has to guess parameter syntax.

## Parameters

### topic (string, optional)
The document to return. Omit it to receive the topic index.

Every MCP tool name is a topic — `proxy_start`, `proxy_stop`, `query`, `manage`, `macro`, `intercept`, `configure`, `security`, `resend_http`, `resend_ws`, `resend_grpc`, `resend_raw`, `fuzz_http`, `fuzz_ws`, `fuzz_grpc`, `fuzz_raw`, `plugin_introspect`, `grpc_schema` — plus the concept topics `getting-started`, `examples`, `template-syntax` and `docs` (this document).

An unknown topic returns an error listing every valid topic.

### section (string, optional)
Return only one heading-anchored section instead of the whole document. Requires `topic`.

- Matching is case-insensitive and whitespace-trimmed.
- Both the literal heading text and its GitHub-style slug work: `section="Variable substitution syntax"` and `section="variable-substitution-syntax"` select the same section.
- Addressable levels are `##` through `####`. Every help document is held to that depth by a test, so no section exists that the index or the unknown-section outline does not list. The `#` document title is not addressable — `docs(topic=X)` already returns it.
- A match includes its sub-sections: selecting an `##` heading returns its `###` and `####` children too.
- When two sections share a heading text, the first is returned with a trailing note saying how many share it. `section=` cannot reach the later ones; call `docs(topic=X)` without `section=` to get the whole document instead.
- An unknown section returns an error listing that topic's `##`–`####` outline, spelled exactly as it must be passed back.

## The index

`docs()` with no arguments lists every topic with its one-line summary, an estimated token cost, and its `##` section names. Use it to decide between a full document and a section fetch.

`est_tokens` is a `chars/4` heuristic, not a tokenizer count. Treat it as an order-of-magnitude hint.

## Usage Examples

### List every topic
```json
// docs
{}
```

### Read a whole tool reference
```json
// docs
{"topic": "fuzz_http"}
```

### Read one section of a large document
```json
// docs
{"topic": "macro", "section": "Variable substitution syntax"}
```

### The same section by slug
```json
// docs
{"topic": "macro", "section": "variable-substitution-syntax"}
```

## From the CLI

The same documents are reachable without a running server, because they are embedded in the binary (USK-1037):

```
yorishiro-proxy docs                                        # the topic index
yorishiro-proxy docs macro                                  # a whole document
yorishiro-proxy docs macro "Variable substitution syntax"   # one section
yorishiro-proxy docs macro --section variable-substitution-syntax
```

The topic and section are bare positional words; `--section` is accepted as an alternative to the second positional, and giving both is an error. This subcommand opens no socket, so it works before `proxy_start`, before MCP registration, and when nothing is listening at all.

Against a *running* server the MCP tool is also reachable through the generic client path, which uses `key=value` instead: `yorishiro-proxy client docs topic=macro section="Variable substitution syntax"`. The two print the same document; only the argument grammar differs.

## Notes

- Documents are returned verbatim from the binary's embedded copy; there is no filesystem or network read, and no output size cap.
- The Output SafetyFilter is not applied to docs results. These are static in-repo documents with no wire-captured content, and masking would corrupt the sample values that `docs(topic="security")` uses to explain the PII presets.
- The same documents remain registered as MCP resources under `yorishiro://help/<topic>` for hosts that browse resources. The docs tool exists because most hosts never fetch a resource on the model's behalf.
