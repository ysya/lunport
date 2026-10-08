import { isValidElement, type ReactElement, type ReactNode } from "react";

/*
 * Helpers for the Keychain's markup tests. A component without hooks can be called to get its element tree. Dialogs render into
 * a portal, which a server render leaves out, so their content is read from the tree instead.
 */

/** What a test reads or presses on an element. */
export type TestProps = { onClick?: () => void; onSelect?: () => void; children?: ReactNode; disabled?: boolean };

/** The words of some markup, with the characters React escapes put back. */
export function text(html: string): string {
  return html
    .replace(/<[^>]*>/g, " ")
    .replace(/&#x27;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ");
}

/** The opening tag of the button labelled `label`, without its closing ">". */
export function buttonTag(html: string, label: string): string {
  const at = html.indexOf(`>${label}<`);
  if (at < 0) throw new Error(`no ${label} button`);
  return html.slice(html.lastIndexOf("<button", at), at);
}

/** The shared Button's class names carry `disabled:` variants, so only the attribute itself says a button is off. */
export const DISABLED = 'disabled=""';

/**
 * The invisible characters `SPOOFED_NAME` carries (a right-to-left override and a zero-width space): none may reach the markup.
 * Built from code points, so no invisible character is in this file.
 */
export const HIDDEN_CHARS = new RegExp(`[${String.fromCodePoint(0x202e, 0x200b)}]`);

/** The text of an element tree, in drawing order. */
export function textIn(node: ReactNode): string {
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textIn).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return textIn(node.props.children);
  return "";
}

/** The elements of a tree made by `type` (a component or a tag name), in drawing order. */
export function elementsOf(node: ReactNode, type: unknown, found: ReactElement<TestProps>[] = []): ReactElement<TestProps>[] {
  if (Array.isArray(node)) node.forEach((child) => elementsOf(child, type, found));
  else if (isValidElement<TestProps>(node)) {
    if (node.type === type) found.push(node);
    elementsOf(node.props.children, type, found);
  }
  return found;
}

/** The elements of a tree that have an `onClick`, in drawing order. */
export function buttonsIn(node: ReactNode, found: ReactElement<TestProps>[] = []): ReactElement<TestProps>[] {
  if (Array.isArray(node)) node.forEach((child) => buttonsIn(child, found));
  else if (isValidElement<TestProps>(node)) {
    if (typeof node.props.onClick === "function") found.push(node);
    buttonsIn(node.props.children, found);
  }
  return found;
}
