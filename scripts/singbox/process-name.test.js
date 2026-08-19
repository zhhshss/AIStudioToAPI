const assert = require("assert");
const { applyProcessName, createProcessName } = require("../../src/utils/ProcessName");

const generated = createProcessName();
assert.match(generated, /^(worker|runtime|service|daemon|agent|task|helper)-[a-f0-9]{6}$/);
assert.ok(generated.length <= 15);

process.env.PROCESS_NAME = "custom-name-too-long";
assert.strictEqual(applyProcessName(), "custom-name-too");
assert.strictEqual(process.title, "custom-name-too");

delete process.env.PROCESS_NAME;
const applied = applyProcessName();
assert.ok(applied.length <= 15);
assert.strictEqual(process.title, applied);

console.log("Process name tests passed.");
