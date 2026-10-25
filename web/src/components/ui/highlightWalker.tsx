/**
 * highlightWalker -- DOMParser-based React tree walker for highlight.js output.
 *
 * Split out of CodeViewer.tsx so that file exports only components (React
 * Fast Refresh). The code below is unchanged.
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

import type { ReactNode } from "react";

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
