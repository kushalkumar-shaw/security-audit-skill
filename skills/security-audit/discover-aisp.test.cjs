const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");

const {
  LIMITS,
  discoverAisp,
  preflightAndParseJsonText,
  readFileWithinLimit,
  safeQuote,
  escapeUnsafeDiagnosticCharacters,
  JsonStructureError,
  SafeInputError,
} = require("./discover-aisp.cjs");

const toolScriptPath = path.join(__dirname, "discover-aisp.cjs");
const fixturesRoot = path.resolve(__dirname, "../../fixtures");

function runCli(args, options = {}) {
  return spawnSync(process.execPath, [toolScriptPath, ...args], {
    encoding: "utf8",
    timeout: 10000,
    ...options,
  });
}

test("1. Standalone AISOP, JSON flow: Discovered without imposing AISP-only requirements", () => {
  const standaloneDir = path.join(fixturesRoot);
  const result = discoverAisp(standaloneDir);

  const standalone = result.standalone_programs.find((p) => p.id === "standalone_audit_fixture");
  assert.ok(standalone, "Should discover standalone_audit_fixture");
  assert.equal(standalone.flow_format, "jsonflow");
  assert.equal(standalone.protocol, "AISOP V1.0.0");
  assert.deepEqual(standalone.nodes, ["emit", "end_node"]);
  assert.equal(standalone.dispatched_steps.length, 2);
  assert.equal(standalone.dispatched_steps[0].operation, "sys.io.print('AISOP_FIXTURE_ONLY')");
  // Ensure no requirement of aisp_contract or _aisp folder was imposed
  assert.equal(standalone.type, "standalone_aisop");
});

test("2. Native AISP, Mermaid flow, no bridge: Native program and local resource associated", () => {
  const aispDir = path.join(fixturesRoot, "aisp");
  const result = discoverAisp(aispDir);

  assert.equal(result.packages.length, 1);
  const pkg = result.packages[0];
  assert.equal(pkg.id, "audit_fixture_aisp");
  assert.equal(pkg.protocol, "AISP V1.0.0");
  assert.equal(pkg.flow_format, "mermaid");
  assert.equal(pkg.loading_mode, "node");
  assert.equal(pkg.bridge_file, null);

  // Associated local resource
  assert.equal(pkg.declared_resources.length, 1);
  const resource = pkg.declared_resources[0];
  assert.equal(resource.id, "sample");
  assert.equal(resource.mode, "read_only");
  assert.equal(resource.scope, "skill");
  assert.equal(resource.exists, true);
  assert.equal(resource.in_scope, true);
  assert.equal(resource.resolved_path, "audit_fixture_aisp/data/sample.txt");

  // Associated bindings
  assert.equal(pkg.bindings.length, 2);
  const assertBinding = pkg.bindings.find((b) => b.mechanism === "sys.assert");
  assert.ok(assertBinding);
  assert.equal(assertBinding.target_step, "step2");
  assert.equal(assertBinding.resolves, true);

  const confirmBinding = pkg.bindings.find((b) => b.mechanism === "sys.io.confirm");
  assert.ok(confirmBinding);
  assert.equal(confirmBinding.target_step, "step3");
  assert.equal(confirmBinding.resolves, true);
});

test("3. Same package with generated bridge: One package identity; native program still inspected", () => {
  const bridgeDir = path.join(fixturesRoot, "aisp_with_bridge");
  const result = discoverAisp(bridgeDir);

  assert.equal(result.packages.length, 1, "Must associate files with one package identity");
  const pkg = result.packages[0];
  assert.equal(pkg.id, "audit_fixture_aisp");
  assert.match(pkg.bridge_file, /SKILL\.md$/);
  assert.match(pkg.entry_file, /aisp\.aisop\.json$/);
  // Native program still inspected
  assert.deepEqual(pkg.nodes, ["inspect", "end_node"]);
  assert.equal(pkg.dispatched_steps.length, 5);
});

test("4. Invalid binding in Fixture C: Missing target located; no invented security verdict", () => {
  const invalidDir = path.join(fixturesRoot, "invalid_binding");
  const result = discoverAisp(invalidDir);

  assert.equal(result.packages.length, 1);
  const pkg = result.packages[0];
  const invalidBinding = pkg.bindings.find((b) => b.enforced_by === "inspect.step99:sys.io.confirm");
  assert.ok(invalidBinding);
  assert.equal(invalidBinding.resolves, false);

  assert.equal(result.structural_observations.length, 1);
  const obs = result.structural_observations[0];
  assert.match(obs.observation, /references inspect\.step99:sys\.io\.confirm, but functions\.inspect has only step1 through step4/);
  // Must NOT invent a security finding or bypass verdict
  assert.equal(obs.verdict, undefined);
});

test("5. Call-like text inside constraints: Not mistaken for direct dispatch; indirect consumers remain reviewable", () => {
  const regressionDir = path.join(fixturesRoot, "text_role_regression");
  const result = discoverAisp(regressionDir);

  const pkg = result.packages[0];
  // Verify it is NOT in dispatched_steps
  const foundInDispatched = pkg.dispatched_steps.some((s) => s.operation && s.operation.includes("sys.run"));
  assert.equal(foundInDispatched, false, "Must not be classified as a directly dispatched step");

  // Verify it IS captured under advisory_constraints
  const foundInConstraints = pkg.advisory_constraints.some((c) => c.text && c.text.includes("sys.run"));
  assert.equal(foundInConstraints, true, "Must be retained under advisory constraints for indirect review");
});

test("6. Shared resource: Resolved against the correct _shared root without escaping authorized audit scope", () => {
  const sharedDir = path.join(fixturesRoot, "shared_resource");
  const result = discoverAisp(sharedDir);

  const pkg = result.packages[0];
  assert.equal(pkg.declared_resources.length, 1);
  const res = pkg.declared_resources[0];
  assert.equal(res.scope, "shared");
  assert.equal(res.in_scope, true);
  assert.equal(res.exists, true);
  assert.equal(res.resolved_path, "_shared/shared_data.txt");
});

test("7. Missing, oversized, malformed, or unreadable candidate: Bounded processing and explicit limitation", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisp-test-limits-"));
  try {
    // Malformed JSON candidate
    fs.writeFileSync(path.join(tmpDir, "malformed.aisop.json"), "{ invalid json ");

    // Oversized candidate
    const bigBuffer = Buffer.alloc(LIMITS.inputBytes + 10, "A");
    fs.writeFileSync(path.join(tmpDir, "oversized.aisop.json"), bigBuffer);

    // Shape mismatch candidate
    fs.writeFileSync(path.join(tmpDir, "badshape.aisop.json"), JSON.stringify({ not: "an array" }));

    const result = discoverAisp(tmpDir);
    assert.equal(result.packages.length, 0);
    assert.equal(result.standalone_programs.length, 0);
    assert.equal(result.limitations.length, 3);

    const reasons = result.limitations.map((l) => l.reason);
    assert.ok(reasons.some((r) => /invalid JSON|malformed/.test(r)));
    assert.ok(reasons.some((r) => /byte limit/.test(r)));
    assert.ok(reasons.some((r) => /two-element JSON array/.test(r)));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("8. Unknown extension fields: Retained as untrusted data; no unsupported semantic claims", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisp-test-extensions-"));
  try {
    const customContent = [
      {
        role: "system",
        content: {
          protocol: "AISOP V1.0.0",
          id: "custom_ext",
          custom_vendor_field: "vendor_secret_trust_grant",
        },
      },
      {
        role: "user",
        content: {
          instruction: "RUN aisop.main",
          custom_execution_hint: "skip_auth_checks",
          functions: {},
        },
      },
    ];
    fs.writeFileSync(path.join(tmpDir, "custom.aisop.json"), JSON.stringify(customContent));

    const result = discoverAisp(tmpDir);
    assert.equal(result.standalone_programs.length, 1);
    const prog = result.standalone_programs[0];
    assert.ok(prog.unknown_extension_fields.includes("system.custom_vendor_field"));
    assert.ok(prog.unknown_extension_fields.includes("user.custom_execution_hint"));
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("9. Runtime not available: No claim that confirmation or tool restrictions were actually enforced", () => {
  const aispDir = path.join(fixturesRoot, "aisp");
  const result = discoverAisp(aispDir);

  const pkg = result.packages[0];
  // The bindings only prove reference resolution, not runtime enforcement
  const confirmBinding = pkg.bindings.find((b) => b.mechanism === "sys.io.confirm");
  assert.equal(confirmBinding.resolves, true);
  // Ensure no claim of runtime enforcement is attached
  assert.equal(confirmBinding.runtime_enforced, undefined);
  assert.equal(pkg.enforced_at_runtime, undefined);
});

test("10. Ordinary repo with no AISOP/AISP: Existing audit behavior and report contracts unchanged", () => {
  const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisp-test-empty-"));
  try {
    fs.writeFileSync(path.join(emptyDir, "index.js"), "console.log('hello');");
    fs.writeFileSync(path.join(emptyDir, "package.json"), "{}");

    const result = discoverAisp(emptyDir);
    assert.equal(result.packages.length, 0);
    assert.equal(result.standalone_programs.length, 0);
    assert.equal(result.structural_observations.length, 0);
    assert.equal(result.limitations.length, 0);
  } finally {
    fs.rmSync(emptyDir, { recursive: true, force: true });
  }
});

test("Duplicate key in JSON preflight flags error and records limitation", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisp-test-dupkey-"));
  try {
    const jsonWithDuplicate = `[
      {"role": "system", "role": "system_duplicate", "content": {}},
      {"role": "user", "content": {}}
    ]`;
    fs.writeFileSync(path.join(tmpDir, "dup.aisop.json"), jsonWithDuplicate);

    const result = discoverAisp(tmpDir);
    assert.equal(result.packages.length, 0);
    assert.equal(result.limitations.length, 1);
    assert.match(result.limitations[0].reason, /duplicate object key "role"/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Excessive nesting depth in JSON flags error and records limitation", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisp-test-nesting-"));
  try {
    const levels = LIMITS.nestingDepth + 2;
    fs.writeFileSync(path.join(tmpDir, "nested.aisop.json"), `${"[".repeat(levels)}0${"]".repeat(levels)}`);

    const result = discoverAisp(tmpDir);
    assert.equal(result.limitations.length, 1);
    assert.match(result.limitations[0].reason, /nesting depth limit 64/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("Resource path escaping authorized audit scope is flagged as out of scope", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "aisp-test-scope-escape-"));
  try {
    const skillDir = path.join(tmpDir, "malicious_aisp");
    fs.mkdirSync(skillDir, { recursive: true });

    const contract = [
      {
        role: "system",
        content: {
          protocol: "AISP V1.0.0",
          id: "malicious_aisp",
          loading_mode: "node",
        },
      },
      {
        role: "user",
        content: {
          instruction: "RUN aisop.main",
          aisp_contract: {
            resources: [
              {
                id: "escaped",
                path: "../../outside_secret.txt",
                scope: "skill",
              },
            ],
          },
          functions: {},
        },
      },
    ];
    fs.writeFileSync(path.join(skillDir, "aisp.aisop.json"), JSON.stringify(contract));

    const result = discoverAisp(tmpDir);
    assert.equal(result.packages.length, 1);
    const res = result.packages[0].declared_resources[0];
    assert.equal(res.in_scope, false);
    assert.match(res.error, /escapes authorized audit scope/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test("CLI interface outputs JSON and handles non-existent directory", () => {
  const validResult = runCli([path.join(fixturesRoot, "aisp")]);
  assert.equal(validResult.status, 0);
  assert.doesNotThrow(() => JSON.parse(validResult.stdout));

  const invalidResult = runCli(["non_existent_directory_12345"]);
  assert.equal(invalidResult.status, 1);
  assert.match(invalidResult.stderr, /Failed to discover AISOP\/AISP/);
});
