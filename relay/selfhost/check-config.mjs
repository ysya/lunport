// Fails the image build when workerd.capnp drifts from ../wrangler.jsonc: the self-hosted relay
// must run with the Cloudflare deployment's compatibility date and Durable Object classes.
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** Drop `//` and `/* *\/` comments outside strings, so JSON.parse can read a .jsonc file. */
function stripJsonComments(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      for (i++; i < text.length && text[i] !== '"'; i++) if (text[i] === "\\") i++;
      out += text.slice(start, i + 1);
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
      out += "\n";
    } else if (c === "/" && text[i + 1] === "*") {
      i = text.indexOf("*/", i + 2) + 1;
      if (i === 0) throw new Error("unterminated block comment in wrangler.jsonc");
    } else {
      out += c;
    }
  }
  return out;
}

const wrangler = JSON.parse(stripJsonComments(readFileSync(join(here, "../wrangler.jsonc"), "utf8")));
const capnp = readFileSync(join(here, "workerd.capnp"), "utf8");

const problems = [];
const capnpDate = /compatibilityDate = "([^"]+)"/.exec(capnp)?.[1];
if (capnpDate !== wrangler.compatibility_date) {
  problems.push(`compatibilityDate is ${capnpDate}, wrangler.jsonc has ${wrangler.compatibility_date}`);
}

const sqliteClasses = new Set((wrangler.migrations ?? []).flatMap((m) => m.new_sqlite_classes ?? []));
const capnpBindings = new Map(
  [...capnp.matchAll(/\(name = "(\w+)", durableObjectNamespace = "(\w+)"\)/g)].map((m) => [m[1], m[2]]),
);
const capnpSqlClasses = new Set(
  [...capnp.matchAll(/\(className = "(\w+)", uniqueKey = "[^"]+", enableSql = true\)/g)].map((m) => m[1]),
);
for (const { name, class_name } of wrangler.durable_objects?.bindings ?? []) {
  if (capnpBindings.get(name) !== class_name) problems.push(`binding ${name} → ${class_name} is missing`);
  if (!sqliteClasses.has(class_name)) problems.push(`${class_name} is not a SQLite class in wrangler.jsonc`);
  if (!capnpSqlClasses.has(class_name)) problems.push(`${class_name} needs a namespace with enableSql = true`);
}
if (capnpBindings.size !== (wrangler.durable_objects?.bindings ?? []).length) {
  problems.push(`workerd.capnp declares ${capnpBindings.size} bindings, wrangler.jsonc ${wrangler.durable_objects?.bindings?.length ?? 0}`);
}

if (problems.length > 0) {
  console.error(`selfhost/workerd.capnp does not match wrangler.jsonc:\n  - ${problems.join("\n  - ")}`);
  process.exit(1);
}
console.log("selfhost/workerd.capnp matches wrangler.jsonc");
