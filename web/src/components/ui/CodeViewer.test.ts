import { describe, expect, it } from "vitest";
import {
  walkHighlightedRoot,
  type NodeLike,
} from "./CodeViewer.js";
import {
  isValidElement,
  type ReactElement,
  type ReactNode,
} from "react";

// ---------------------------------------------------------------------------
// NodeLike fixture helpers
// ---------------------------------------------------------------------------
//
// We do NOT use a real DOM here. Vitest runs in Node mode (no jsdom), and the
// walker is intentionally typed against a minimal NodeLike interface so the
// tree-walk logic can be tested with plain object literals. The runtime path
// in CodeViewer.tsx still feeds DOMParser output into walkHighlightedRoot, so
// these fixtures exercise the same contract a real DOM would produce.

const NODE_TYPE_ELEMENT = 1;
const NODE_TYPE_TEXT = 3;

function text(value: string): NodeLike {
  return {
    nodeType: NODE_TYPE_TEXT,
    textContent: value,
    childNodes: [],
  };
}

function elem(
  tagName: string,
  attrs: Record<string, string>,
  children: NodeLike[],
): NodeLike {
  return {
    nodeType: NODE_TYPE_ELEMENT,
    tagName: tagName.toUpperCase(),
    childNodes: children,
    textContent: childrenTextContent(children),
    getAttribute: (name) => attrs[name] ?? null,
  };
}

function span(className: string, children: NodeLike[]): NodeLike {
  return elem("span", { class: className }, children);
}

function root(children: NodeLike[]): NodeLike {
  return elem("div", {}, children);
}

function childrenTextContent(children: NodeLike[]): string {
  let out = "";
  for (const c of children) {
    if (c.nodeType === NODE_TYPE_TEXT) {
      out += c.textContent ?? "";
    } else {
      out += c.textContent ?? "";
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// React tree introspection helpers
// ---------------------------------------------------------------------------

interface Inspected {
  /** "text" for strings, otherwise the React component / tag name. */
  type: string;
  /** className for elements; absent for text. */
  className?: string;
  /** Text content for text nodes. */
  text?: string;
  /** Recursive children for elements and Fragments. */
  children?: Inspected[];
  /** True if this node has any prop other than `children`/`className`/`key`. */
  hasExtraProps?: boolean;
  /** List of extra (non-allow-listed) prop names — used by tests. */
  extraPropNames?: string[];
}

const ALLOWED_PROPS = new Set(["children", "className", "key"]);

function inspect(node: ReactNode): Inspected[] {
  if (node === null || node === undefined || node === false || node === true) {
    return [];
  }
  if (typeof node === "string" || typeof node === "number") {
    return [{ type: "text", text: String(node) }];
  }
  if (Array.isArray(node)) {
    const out: Inspected[] = [];
    for (const c of node) out.push(...inspect(c));
    return out;
  }
  if (isValidElement(node)) {
    const el = node as ReactElement<Record<string, unknown>>;
    const props = el.props as Record<string, unknown>;
    const typeName =
      typeof el.type === "string"
        ? el.type
        : (el.type as { displayName?: string; name?: string })
            .displayName ??
          (el.type as { name?: string }).name ??
          "Fragment";
    const childrenProp = props["children"];
    const childInspected: Inspected[] = [];
    if (childrenProp !== undefined) {
      childInspected.push(...inspect(childrenProp as ReactNode));
    }
    const extraPropNames: string[] = [];
    for (const key of Object.keys(props)) {
      if (!ALLOWED_PROPS.has(key)) extraPropNames.push(key);
    }
    // Symbol(react.fragment) shows up as Symbol; treat as Fragment.
    const finalType =
      typeof el.type === "symbol" ? "Fragment" : typeName;
    const result: Inspected = {
      type: finalType,
      className:
        typeof props["className"] === "string"
          ? (props["className"] as string)
          : undefined,
      children: childInspected,
    };
    if (extraPropNames.length > 0) {
      result.hasExtraProps = true;
      result.extraPropNames = extraPropNames;
    }
    return [result];
  }
  return [];
}

/** Flatten a row into one Inspected[] without intervening Fragments. */
function flattenRow(row: ReactNode[]): Inspected[] {
  const out: Inspected[] = [];
  for (const node of row) {
    out.push(...inspect(node));
  }
  // Inline Fragments so callers can assert the actual element shape.
  return inlineFragments(out);
}

function inlineFragments(nodes: Inspected[]): Inspected[] {
  const out: Inspected[] = [];
  for (const n of nodes) {
    if (n.type === "Fragment") {
      out.push(...inlineFragments(n.children ?? []));
    } else {
      const copy: Inspected = { ...n };
      if (copy.children) copy.children = inlineFragments(copy.children);
      out.push(copy);
    }
  }
  return out;
}

/** Concatenate all text descendants of an Inspected tree. */
function inspectedText(nodes: Inspected[]): string {
  let out = "";
  for (const n of nodes) {
    if (n.type === "text") {
      out += n.text ?? "";
    } else if (n.children) {
      out += inspectedText(n.children);
    }
  }
  return out;
}

/** Walk an Inspected tree and return every element node. */
function allElements(nodes: Inspected[]): Inspected[] {
  const out: Inspected[] = [];
  for (const n of nodes) {
    if (n.type !== "text") out.push(n);
    if (n.children) out.push(...allElements(n.children));
  }
  return out;
}

// ---------------------------------------------------------------------------
// walkHighlightedRoot — table-driven cases
// ---------------------------------------------------------------------------

describe("walkHighlightedRoot", () => {
  it("returns a single empty row for an empty root", () => {
    const rows = walkHighlightedRoot(root([]));
    expect(rows).toEqual([[]]);
  });

  it("emits one text node for plain-text input", () => {
    const rows = walkHighlightedRoot(root([text("hello")]));
    expect(rows).toHaveLength(1);
    const flat = flattenRow(rows[0]);
    expect(flat).toHaveLength(1);
    expect(flat[0].type).toBe("text");
    expect(flat[0].text).toBe("hello");
  });

  it("wraps a hljs span correctly", () => {
    // Equivalent of: <span class="hljs-string">"hello"</span>
    const rows = walkHighlightedRoot(
      root([span("hljs-string", [text('"hello"')])]),
    );
    expect(rows).toHaveLength(1);
    const flat = flattenRow(rows[0]);
    expect(flat).toHaveLength(1);
    expect(flat[0].type).toBe("span");
    expect(flat[0].className).toBe("hljs-string");
    expect(inspectedText(flat[0].children ?? [])).toBe('"hello"');
  });

  it("preserves nested spans", () => {
    // <span class="hljs-keyword"><span class="hljs-built_in">x</span></span>
    const rows = walkHighlightedRoot(
      root([
        span("hljs-keyword", [span("hljs-built_in", [text("x")])]),
      ]),
    );
    const flat = flattenRow(rows[0]);
    expect(flat).toHaveLength(1);
    expect(flat[0].type).toBe("span");
    expect(flat[0].className).toBe("hljs-keyword");
    const inner = flat[0].children ?? [];
    const innerEls = allElements(inner);
    expect(innerEls).toHaveLength(1);
    expect(innerEls[0].type).toBe("span");
    expect(innerEls[0].className).toBe("hljs-built_in");
    expect(inspectedText(innerEls[0].children ?? [])).toBe("x");
  });

  it("splits a multi-line span across rows and reopens the span on each row", () => {
    // <span class="hljs-string">"a\nb"</span>
    const rows = walkHighlightedRoot(
      root([span("hljs-string", [text('"a\nb"')])]),
    );
    expect(rows).toHaveLength(2);

    const row0 = flattenRow(rows[0]);
    expect(row0).toHaveLength(1);
    expect(row0[0].type).toBe("span");
    expect(row0[0].className).toBe("hljs-string");
    expect(inspectedText(row0[0].children ?? [])).toBe('"a');

    const row1 = flattenRow(rows[1]);
    expect(row1).toHaveLength(1);
    expect(row1[0].type).toBe("span");
    expect(row1[0].className).toBe("hljs-string");
    expect(inspectedText(row1[0].children ?? [])).toBe('b"');
  });

  it("re-opens nested spans on each row when newline crosses both", () => {
    // <span class="hljs-keyword"><span class="hljs-built_in">a\nb</span></span>
    const rows = walkHighlightedRoot(
      root([
        span("hljs-keyword", [span("hljs-built_in", [text("a\nb")])]),
      ]),
    );
    expect(rows).toHaveLength(2);
    for (let i = 0; i < 2; i++) {
      const flat = flattenRow(rows[i]);
      expect(flat).toHaveLength(1);
      expect(flat[0].type).toBe("span");
      expect(flat[0].className).toBe("hljs-keyword");
      const innerEls = allElements(flat[0].children ?? []);
      expect(innerEls[0].type).toBe("span");
      expect(innerEls[0].className).toBe("hljs-built_in");
    }
    expect(inspectedText(flattenRow(rows[0]))).toBe("a");
    expect(inspectedText(flattenRow(rows[1]))).toBe("b");
  });

  it("splits plain-text content on newlines without any wrapping spans", () => {
    const rows = walkHighlightedRoot(root([text("line1\nline2\nline3")]));
    expect(rows).toHaveLength(3);
    expect(inspectedText(flattenRow(rows[0]))).toBe("line1");
    expect(inspectedText(flattenRow(rows[1]))).toBe("line2");
    expect(inspectedText(flattenRow(rows[2]))).toBe("line3");
    // No spans anywhere.
    for (const row of rows) {
      expect(allElements(flattenRow(row))).toHaveLength(0);
    }
  });

  it("emits empty rows for consecutive newlines", () => {
    const rows = walkHighlightedRoot(root([text("a\n\nb")]));
    expect(rows).toHaveLength(3);
    expect(inspectedText(flattenRow(rows[0]))).toBe("a");
    expect(flattenRow(rows[1])).toEqual([]); // empty line in the middle
    expect(inspectedText(flattenRow(rows[2]))).toBe("b");
  });

  it("degrades hostile elements like <script> to text content", () => {
    // Mimics what DOMParser would build for `<script>alert(1)</script>`:
    // a SCRIPT element with a text child "alert(1)".
    const rows = walkHighlightedRoot(
      root([elem("script", {}, [text("alert(1)")])]),
    );
    const flat = flattenRow(rows[0]);
    // No <script> element in the React tree.
    const els = allElements(flat);
    for (const el of els) {
      expect(el.type).not.toBe("script");
    }
    expect(inspectedText(flat)).toBe("alert(1)");
  });

  it("does not pass through disallowed elements such as <img> or <div>", () => {
    // Voids and block elements that are NOT span — must degrade.
    const rows = walkHighlightedRoot(
      root([
        elem("img", { src: "x", onerror: "alert(1)" }, []),
        text(" mid "),
        elem("div", { onclick: "alert(2)" }, [text("inside")]),
      ]),
    );
    const flat = flattenRow(rows[0]);
    for (const el of allElements(flat)) {
      expect(["span", "Fragment", "text"]).toContain(el.type);
    }
    // The <img> contributes no text (textContent is empty); the div
    // contributes "inside".
    expect(inspectedText(flat)).toBe(" mid inside");
  });

  it("strips disallowed attributes such as onclick from spans", () => {
    // <span class="hljs-string" onclick="alert(1)" style="color:red">x</span>
    const rows = walkHighlightedRoot(
      root([
        elem(
          "span",
          { class: "hljs-string", onclick: "alert(1)", style: "color:red" },
          [text("x")],
        ),
      ]),
    );
    const flat = flattenRow(rows[0]);
    expect(flat).toHaveLength(1);
    expect(flat[0].type).toBe("span");
    expect(flat[0].className).toBe("hljs-string");
    // No onclick / style / onerror props leak into the React element.
    expect(flat[0].hasExtraProps ?? false).toBe(false);
    expect(flat[0].extraPropNames ?? []).toEqual([]);
  });

  it("passes through HTML-entity-decoded text faithfully", () => {
    // DOMParser would have already decoded &amp; -> & by the time the walker
    // sees text. We verify the walker doesn't mangle the decoded form.
    const rows = walkHighlightedRoot(
      root([span("hljs-string", [text("&")])]),
    );
    const flat = flattenRow(rows[0]);
    expect(flat).toHaveLength(1);
    expect(flat[0].type).toBe("span");
    expect(inspectedText(flat[0].children ?? [])).toBe("&");
  });

  it("ignores comment / unknown nodeType nodes", () => {
    const comment: NodeLike = {
      nodeType: 8, // COMMENT_NODE
      textContent: "this is a comment",
      childNodes: [],
    };
    const rows = walkHighlightedRoot(
      root([text("a"), comment, text("b")]),
    );
    expect(inspectedText(flattenRow(rows[0]))).toBe("ab");
  });

  it("handles a span whose getAttribute returns null for class", () => {
    // Defensive: a <span> without class still walks its children.
    const rows = walkHighlightedRoot(
      root([elem("span", {}, [text("x")])]),
    );
    const flat = flattenRow(rows[0]);
    expect(flat).toHaveLength(1);
    expect(flat[0].type).toBe("span");
    // className may be undefined; React treats that as absent.
    expect(flat[0].className).toBeUndefined();
    expect(inspectedText(flat[0].children ?? [])).toBe("x");
  });
});
