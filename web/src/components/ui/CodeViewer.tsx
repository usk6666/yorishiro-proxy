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
 */

import { useState, useMemo, useCallback, useEffect, useRef } from "react";
import hljs from "highlight.js/lib/core";
import json from "highlight.js/lib/languages/json";
import xml from "highlight.js/lib/languages/xml";
import javascript from "highlight.js/lib/languages/javascript";
import css from "highlight.js/lib/languages/css";
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
// Helpers
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

/** Split code into lines and produce highlighted HTML per line. */
function highlightCode(code: string, language: string | null): string {
  if (!language) return escapeHtml(code);
  try {
    const result = hljs.highlight(code, { language });
    return result.value;
  } catch {
    return escapeHtml(code);
  }
}

/** Minimal HTML escape for raw display. */
function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
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

  const lines = useMemo(() => {
    if (!shouldHighlight) {
      return code.split("\n").map((line) => escapeHtml(line));
    }
    // Highlight the entire code then split by newlines.
    // highlight.js returns HTML, so we split on literal newlines
    // that are not inside HTML tags.
    const highlighted = highlightCode(code, language);
    return highlighted.split("\n");
  }, [code, shouldHighlight, language]);

  const lineNumberWidth = useMemo(() => {
    return Math.max(2, String(lines.length).length);
  }, [lines.length]);

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
            {lines.map((lineHtml, i) => (
              <tr key={i} className="code-viewer-line">
                <td
                  className="code-viewer-line-number"
                  style={{ minWidth: `${lineNumberWidth + 1}ch` }}
                >
                  {i + 1}
                </td>
                <td
                  className="code-viewer-line-content"
                  dangerouslySetInnerHTML={{ __html: lineHtml || " " }}
                />
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
