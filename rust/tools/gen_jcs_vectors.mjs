// Writes crates/lunchroom-core/src/jcs/vectors.json: inputs and their RFC 8785 (JCS) canonical form,
// computed with ECMAScript's own JSON.stringify for numbers and strings and the default sort (UTF-16
// code units) for keys, which is what RFC 8785 specifies.
// Usage: node tools/gen_jcs_vectors.mjs crates/lunchroom-core/src/jcs/vectors.json
import { writeFileSync } from "node:fs";

function canon(v) {
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  if (v !== null && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

const inputs = [
  "0", "-0", "1", "-1", "1.0", "4.50", "2e-3", "0.000001", "0.0000001", "1e21", "1e20",
  "123456789012345680000", "9007199254740993", "-9007199254740993", "1.7976931348623157e308",
  "5e-324", "2.2250738585072014e-308", "0.1", "333333333.3333332", "1E400".replace("400", "300"),
  "1e-6", "1e-7", "12345e-10", "100", "1.5e+3", "-1.25e-12", "18446744073709551615",
  "\"\"", "\"a\\\"b\\\\c\"", "\"\\u0000\\u0001\\u001f\\u007f\"", "\"\\b\\f\\n\\r\\t\"",
  "\"\\u2028\\u2029\"", "\"€😀\"", "\"\\ud83d\\ude00\"", "true", "false", "null", "[]", "{}",
  "[1,\"two\",[3,{\"x\":null}]]",
  "{\"b\":1,\"a\":2,\"aa\":3,\"A\":4}",
  "{\"\\u20ac\":1,\"\\r\":2,\"\\ud83d\\ude00\":3,\"\\ufb33\":4,\"1\":5,\"\\u0080\":6,\"\\u00f6\":7}",
  "{ \"command\" : \"git push origin main\", \"description\": \"push\", \"timeout\": 120000 }",
  "{\"file_path\":\"/tmp/x\",\"old_string\":\"a\\nb\",\"new_string\":\"c\\td\",\"replace_all\":false}",
];
// A sweep of doubles across magnitudes, written the way JSON input would carry them.
let seed = 42;
const rnd = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648);
for (let i = 0; i < 300; i++) {
  const e = Math.floor(rnd() * 60) - 30;
  const x = (rnd() - 0.5) * Math.pow(10, e);
  inputs.push(x.toPrecision(1 + Math.floor(rnd() * 17)));
}
// Doubles from random 64-bit patterns, so every exponent range appears; each is written the way
// ECMAScript writes it, which reads back as the same double.
inputs.push("198.1866359710693");
const view = new DataView(new ArrayBuffer(8));
let bits = 0x9e3779b97f4a7c15n;
for (let i = 0; i < 5000; i++) {
  bits = (bits * 6364136223846793005n + 1442695040888963407n) & 0xffffffffffffffffn;
  view.setBigUint64(0, bits);
  const x = view.getFloat64(0);
  if (Number.isFinite(x)) inputs.push(String(x));
}
const vectors = inputs.map((input) => ({ input, canonical: canon(JSON.parse(input)) }));
writeFileSync(process.argv[2], JSON.stringify(vectors, null, 1) + "\n");
console.log(vectors.length, "vectors written");
