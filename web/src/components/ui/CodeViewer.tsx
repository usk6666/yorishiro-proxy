/**
 * CodeViewer -- Syntax-highlighted code display with line numbers.
 *
 * Features:
 * - Content-Type based language auto-detection
 * - Line numbers
 * - Copy button
 * - Word-wrap toggle
 * - Raw / Highlighted toggle
 * - Lazy highlighting for large bodies (>10 KB)
 *
 * Uses highlight.js (BSD-3-Clause) for syntax highlighting.
 *
 * Security: highlight.js output is rendered via a DOMParser-based React tree
 * walker rather than `dangerouslySetInnerHTML`. Only `<span class="hljs-...">`
 * elements and text nodes are admitted; any other element degrades to its
 * `textContent`. This is the front-line XSS defense for hljs-rendered code in
 * the WebUI (no CSP yet — see USK-743). The walker also fixes the latent bug
 * where `highlighted.split("\n")` could break tags whose textContent crosses a
 * line boundary: each `\n` closes the current row and reopens any active
 * `<span>` parents on the next row, preserving syntax coloring across lines.
 */

import hljs from "highlight.js/lib/core";
import css from "highlight.js/lib/languages/css";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import "./CodeViewer.css";

// Register only the languages we need to keep the bundle small.
hljs.registerLanguage("json", json);
hljs.registerLanguage("xml", xml); // Also covers HTML
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("css", css);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Bodies larger than this (in characters) get lazy / opt-in highlighting. */
const LARGE_BODY_THRESHOLD = 10_240;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CodeViewerProps {
  /** The text content to display. */
  code: string;
  /** Optional Content-Type header value for language auto-detection. */
  contentType?: string;
  /** If true, show a "large body" notice and let user opt-in to highlighting. */
  maxHighlightSize?: number;
  /** Additional CSS class name. */
  className?: string;
}

// ---------------------------------------------------------------------------
// Helpers — language detection / highlighting
// ---------------------------------------------------------------------------

/** Map a Content-Type value to a highlight.js language name. */
function detectLanguage(contentType: string): string | null {
  const ct = contentType.toLowerCase();
  if (ct.includes("application/json") || ct.includes("+json")) return "json";
  if (ct.includes("text/html")) return "xml";
  if (ct.includes("text/xml") || ct.includes("application/xml") || ct.includes("+xml")) return "xml";
  if (ct.includes("text/javascript") || ct.includes("application/javascript")) return "javascript";
  if (ct.includes("text/css")) return "css";
  return null;
}

/** Run hljs on `code` and return its HTML string, or null on error. */
function highlightCode(code: string, language: string | null): string | null {
  if (!language) return null;
  try {
    const result = hljs.highlight(code, { language });
    return result.value;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// DOMParser-based React tree walker
// ---------------------------------------------------------------------------

/**
 * Minimal DOM-shaped node interface used by the walker. Compatible with the
 * standard `Node` / `Element` types but expressed as the smallest surface the
 * walker actually needs, so unit tests can construct fixtures without a real
 * DOM environment.
 */
export interface NodeLike {
  /** 1 = element, 3 = text. Other values are ignored. */
  nodeType: number;
  /** Concatenated text content of this node and all descendants. */
  textContent: string | null;
  /** Upper-case tag name for elements; absent for text nodes. */
  tagName?: string;
  /** Child nodes; empty array for text nodes. */
  childNodes: ArrayLike<NodeLike>;
  /** Returns the value of the named attribute, or null if absent. */
  getAttribute?: (name: string) => string | null;
}

/** Standard DOM Node type identifiers (subset). */
const NODE_TYPE_ELEMENT = 1;
const NODE_TYPE_TEXT = 3;

/**
 * Stack frame describing an ancestor `<span>` that must be re-opened on every
 * new row so syntax coloring continues across line boundaries.
 */
interface SpanFrame {
  /** className copied from the source span. May be undefined / empty. */
  className: string | undefined;
}

/** Mutable per-walk state for line emission. */
interface WalkState {
  rows: ReactNode[][];
  /** Index of the current row in `rows`. Always `>= 0`. */
  currentRow: number;
  /** Active span ancestors, outermost first. */
  spanStack: SpanFrame[];
  /** Monotonic counter for stable React keys. */
  keyCounter: number;
}

/**
 * Wrap `nodes` with the given span frames, innermost frame as the outermost
 * React element. (Frames are stored outermost-first; each frame represents an
 * open ancestor span, so iterating in reverse re-creates the original nesting.)
 */
function wrapWithSpans(
  nodes: ReactNode[],
  frames: SpanFrame[],
  keyPrefix: string,
): ReactNode {
  if (nodes.length === 0) return null;
  let wrapped: ReactNode = nodes.length === 1 ? nodes[0] : <>{nodes}</>;
  for (let i = frames.length - 1; i >= 0; i--) {
    const frame = frames[i];
    wrapped = (
      <span
        key={`${keyPrefix}-w${i}`}
        className={frame.className || undefined}
      >
        {wrapped}
      </span>
    );
  }
  return wrapped;
}

/**
 * Append `node` to the current row (under the current span stack). Each call
 * produces one wrapped React element so spans across multiple appends share
 * structure rather than being merged.
 */
function appendNode(state: WalkState, node: ReactNode, keyPrefix: string): void {
  const wrapped = wrapWithSpans([node], state.spanStack, keyPrefix);
  if (wrapped !== null && wrapped !== undefined) {
    state.rows[state.currentRow].push(wrapped);
  }
}

/**
 * Walk a NodeLike tree, accumulating React nodes into `state.rows`. Splits
 * text-node content on `\n` to generate per-line rows; reopens active span
 * parents on each new row.
 */
function walkInto(node: NodeLike, state: WalkState): void {
  if (node.nodeType === NODE_TYPE_TEXT) {
    const text = node.textContent ?? "";
    if (text.length === 0) return;
    // Split on newline; each segment except the last belongs to the current
    // row and triggers a row break.
    let start = 0;
    for (let i = 0; i < text.length; i++) {
      if (text.charCodeAt(i) === 10 /* \n */) {
        const segment = text.slice(start, i);
        if (segment.length > 0) {
          const k = `t${state.keyCounter++}`;
          appendNode(state, segment, k);
        }
        // Start a new row.
        state.rows.push([]);
        state.currentRow++;
        start = i + 1;
      }
    }
    if (start < text.length) {
      const segment = text.slice(start);
      const k = `t${state.keyCounter++}`;
      appendNode(state, segment, k);
    }
    return;
  }

  if (node.nodeType !== NODE_TYPE_ELEMENT) {
    // Comments, CDATA, etc. — ignore.
    return;
  }

  // Element node. Only <span> contributes structure; everything else degrades
  // to its textContent (defensive — hljs only emits <span class="hljs-...">,
  // but the walker must not pass arbitrary attacker-influenced elements
  // through to React).
  const tagName = (node.tagName ?? "").toUpperCase();
  if (tagName !== "SPAN") {
    const text = node.textContent ?? "";
    if (text.length === 0) return;
    // Re-walk the element as if it were a text node containing its
    // textContent. This preserves \n splitting within the foreign element.
    walkInto(
      {
        nodeType: NODE_TYPE_TEXT,
        textContent: text,
        childNodes: [],
      },
      state,
    );
    return;
  }

  // Genuine <span>. Extract only the `class` attribute; ignore everything
  // else (style, onclick, data-*, etc.) so attacker-controlled attributes
  // cannot reach the React tree.
  const classAttr = node.getAttribute?.("class") ?? null;
  state.spanStack.push({ className: classAttr ?? undefined });
  const children = node.childNodes;
  for (let i = 0; i < children.length; i++) {
    walkInto(children[i], state);
  }
  state.spanStack.pop();
}

/**
 * Convert a NodeLike root (whose children are the highlighted content) into an
 * array of rows. Each row is a flat array of React nodes that should be
 * concatenated into a single `<td>` line. Exported for unit testing.
 */
export function walkHighlightedRoot(root: NodeLike): ReactNode[][] {
  const state: WalkState = {
    rows: [[]],
    currentRow: 0,
    spanStack: [],
    keyCounter: 0,
  };
  const children = root.childNodes;
  for (let i = 0; i < children.length; i++) {
    walkInto(children[i], state);
  }
  return state.rows;
}

/**
 * Parse highlight.js output (or any HTML fragment) into row arrays via
 * DOMParser. Returns rows split on text-node `\n`s, with active span parents
 * reopened on each row.
 *
 * Returns null if DOMParser is unavailable (non-browser environments) — the
 * caller should fall back to treating the input as plain text.
 */
export function htmlToRows(html: string): ReactNode[][] | null {
  if (typeof DOMParser === "undefined") return null;
  // Wrap in a single container so the walker has one root to iterate over.
  // text/html parsing strips disallowed-in-body elements like <html>/<head>
  // when used as the document, but a <div> wrapper in <body> is preserved.
  const doc = new DOMParser().parseFromString(
    `<!DOCTYPE html><html><body><div id="r">${html}</div></body></html>`,
    "text/html",
  );
  const root = doc.getElementById("r");
  if (!root) return [[]];
  return walkHighlightedRoot(root as unknown as NodeLike);
}

/**
 * Plain-text-to-rows: split on `\n`. Used for the raw / non-highlighted path.
 */
function plainTextToRows(text: string): ReactNode[][] {
  const rows: ReactNode[][] = [];
  const parts = text.split("\n");
  for (let i = 0; i < parts.length; i++) {
    const segment = parts[i];
    rows.push(segment.length > 0 ? [segment] : []);
  }
  return rows;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CodeViewer({
  code,
  contentType = "",
  maxHighlightSize = LARGE_BODY_THRESHOLD,
  className,
}: CodeViewerProps) {
  const language = useMemo(() => detectLanguage(contentType), [contentType]);
  const isLarge = code.length > maxHighlightSize;

  const [wordWrap, setWordWrap] = useState(true);
  const [showHighlighted, setShowHighlighted] = useState(!isLarge);
  const [copied, setCopied] = useState(false);
  const copyTimeoutRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Reset highlight opt-in when content changes
  useEffect(() => {
    setShowHighlighted(!isLarge);
  }, [isLarge, code]);

  // Cleanup copy timeout
  useEffect(() => {
    return () => {
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
    };
  }, []);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      if (copyTimeoutRef.current) clearTimeout(copyTimeoutRef.current);
      copyTimeoutRef.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      // Fallback: ignore if clipboard API is unavailable
    }
  }, [code]);

  const shouldHighlight = showHighlighted && language !== null;

  const rows = useMemo<ReactNode[][]>(() => {
    if (!shouldHighlight) {
      return plainTextToRows(code);
    }
    const highlightedHtml = highlightCode(code, language);
    if (highlightedHtml === null) {
      return plainTextToRows(code);
    }
    const parsed = htmlToRows(highlightedHtml);
    if (parsed === null) {
      // DOMParser unavailable (should not happen in browsers); render raw
      // text rather than risk passing the HTML string through unparsed.
      return plainTextToRows(code);
    }
    return parsed;
  }, [code, shouldHighlight, language]);

  const lineNumberWidth = useMemo(() => {
    return Math.max(2, String(rows.length).length);
  }, [rows.length]);

  if (!code) {
    return <div className="code-viewer-empty">No content</div>;
  }

  const wrapperClasses = [
    "code-viewer",
    wordWrap ? "code-viewer--wrap" : "",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={wrapperClasses}>
      {/* Toolbar */}
      <div className="code-viewer-toolbar">
        <div className="code-viewer-toolbar-left">
          {language && (
            <button
              className={`code-viewer-toggle ${showHighlighted ? "code-viewer-toggle--active" : ""}`}
              onClick={() => setShowHighlighted((v) => !v)}
              title={showHighlighted ? "Show raw text" : "Show highlighted"}
            >
              {showHighlighted ? "Highlighted" : "Raw"}
            </button>
          )}
          <button
            className={`code-viewer-toggle ${wordWrap ? "code-viewer-toggle--active" : ""}`}
            onClick={() => setWordWrap((v) => !v)}
            title={wordWrap ? "Disable word wrap" : "Enable word wrap"}
          >
            Wrap
          </button>
        </div>
        <div className="code-viewer-toolbar-right">
          {isLarge && !showHighlighted && language && (
            <span className="code-viewer-large-hint">
              Large body ({Math.round(code.length / 1024)}KB)
            </span>
          )}
          <button
            className="code-viewer-copy-btn"
            onClick={handleCopy}
            title="Copy to clipboard"
          >
            {copied ? "Copied!" : "Copy"}
          </button>
        </div>
      </div>

      {/* Code area */}
      <div className="code-viewer-scroll">
        <table className="code-viewer-table">
          <tbody>
            {rows.map((rowNodes, i) => (
              <tr key={i} className="code-viewer-line">
                <td
                  className="code-viewer-line-number"
                  style={{ minWidth: `${lineNumberWidth + 1}ch` }}
                >
                  {i + 1}
                </td>
                <td className="code-viewer-line-content">
                  {rowNodes.length > 0 ? (
                    <Fragment>{rowNodes}</Fragment>
                  ) : (
                    " "
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
