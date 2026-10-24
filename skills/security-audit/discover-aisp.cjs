#!/usr/bin/env node

/**
 * Discovers, inventories, and structurally summarizes in-scope AISOP programs
 * (*.aisop.json) and native AISP skill packages (*_aisp/aisp.aisop.json).
 *
 * Usage: node discover-aisp.cjs <target-directory>
 *
 * This tool is read-only and static: it inventories and inspects structural
 * boundaries without interpreting or executing target instructions, scripts,
 * or system calls.
 */

const fs = require("node:fs");
const path = require("node:path");
const { TextDecoder } = require("node:util");

const LIMITS = Object.freeze({
  inputBytes: 5 * 1024 * 1024,
  maxFiles: 1000,
  maxDepth: 32,
  nestingDepth: 64,
  collectionItems: 1000,
  objectFields: 1000,
  preflightValues: 500000,
  maxObservations: 100,
  maxLimitations: 100,
});

const UTF8_DECODER = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const UNSAFE_DIAGNOSTIC_CHARACTER = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Default_Ignorable_Code_Point}]/gu;
const MAX_DIAGNOSTIC_STRING_LENGTH = 256;

const HAS_SAFE_INPUT_OPEN = Number.isInteger(fs.constants.O_NOFOLLOW) &&
  fs.constants.O_NOFOLLOW !== 0 &&
  Number.isInteger(fs.constants.O_NONBLOCK) &&
  fs.constants.O_NONBLOCK !== 0;

class JsonStructureError extends Error {}
class SafeInputError extends Error {}

function escapeUnsafeDiagnosticCharacters(value) {
  return String(value).replace(UNSAFE_DIAGNOSTIC_CHARACTER, (character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, "0")}`
      : `\\u{${codePoint.toString(16)}}`;
  });
}

function safeQuote(value) {
  let serialized;
  if (typeof value === "string") {
    const clipped = value.length > MAX_DIAGNOSTIC_STRING_LENGTH
      ? `${value.slice(0, MAX_DIAGNOSTIC_STRING_LENGTH)}...`
      : value;
    serialized = JSON.stringify(clipped);
  } else if (value === null || typeof value === "boolean") {
    serialized = String(value);
  } else if (typeof value === "number" && Number.isFinite(value)) {
    serialized = String(value);
  } else {
    serialized = `"<${Array.isArray(value) ? "array" : typeof value}>"`;
  }
  return escapeUnsafeDiagnosticCharacters(serialized);
}

function isWhitespace(character) {
  return character === " " || character === "\t" || character === "\r" || character === "\n";
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function normalizeRelativePath(relPath) {
  return relPath.split(path.sep).join("/");
}

function preflightAndParseJsonText(contents) {
  const containers = [];
  let rootState = "value";
  let inString = false;
  let escaped = false;
  let totalValues = 0;
  let stringStart = 0;
  let isCurrentStringKey = false;

  function fail(message) {
    throw new JsonStructureError(`input ${message}`);
  }

  function currentContainer() {
    return containers[containers.length - 1];
  }

  function countValue() {
    totalValues++;
    if (totalValues > LIMITS.preflightValues) {
      fail(`exceeds ${LIMITS.preflightValues} total value limit`);
    }
  }

  function beginValue() {
    const container = currentContainer();
    if (!container) {
      if (rootState !== "value") fail("has malformed JSON structure");
      rootState = "end";
    } else if (container.type === "array") {
      if (container.state !== "firstValueOrEnd" && container.state !== "value") {
        fail("has malformed JSON array structure");
      }
      container.items++;
      if (container.items > LIMITS.collectionItems) {
        fail(`exceeds ${LIMITS.collectionItems} item array limit`);
      }
      container.state = "commaOrEnd";
    } else {
      if (container.state !== "value") fail("has malformed JSON object structure");
      container.state = "commaOrEnd";
    }
    countValue();
  }

  function beginString(index) {
    const container = currentContainer();
    if (container && container.type === "object" &&
        (container.state === "firstKeyOrEnd" || container.state === "key")) {
      container.fields++;
      if (container.fields > LIMITS.objectFields) {
        fail(`exceeds ${LIMITS.objectFields} field object limit`);
      }
      container.state = "colon";
      isCurrentStringKey = true;
    } else {
      beginValue();
      isCurrentStringKey = false;
    }
    inString = true;
    stringStart = index + 1;
  }

  function finishString(index) {
    if (isCurrentStringKey) {
      const container = currentContainer();
      const rawKey = contents.slice(stringStart, index);
      let parsedKey;
      try {
        parsedKey = JSON.parse(`"${rawKey}"`);
      } catch {
        fail("contains malformed string escape in object key");
      }
      if (container.seenKeys.has(parsedKey)) {
        fail(`has duplicate object key ${safeQuote(parsedKey)}`);
      }
      container.seenKeys.add(parsedKey);
      isCurrentStringKey = false;
    }
    inString = false;
  }

  function beginContainer(type) {
    beginValue();
    if (containers.length >= LIMITS.nestingDepth) {
      fail(`exceeds nesting depth limit ${LIMITS.nestingDepth}`);
    }
    containers.push(type === "array"
      ? { type, state: "firstValueOrEnd", items: 0 }
      : { type, state: "firstKeyOrEnd", fields: 0, seenKeys: new Set() });
  }

  function closeContainer(type) {
    const container = currentContainer();
    if (!container || container.type !== type) fail("has mismatched JSON containers");
    const canClose = type === "array"
      ? container.state === "firstValueOrEnd" || container.state === "commaOrEnd"
      : container.state === "firstKeyOrEnd" || container.state === "commaOrEnd";
    if (!canClose) fail(`has malformed JSON ${type} structure`);
    containers.pop();
  }

  for (let index = 0; index < contents.length; index++) {
    const character = contents[index];
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === "\"") {
        finishString(index);
      }
      continue;
    }

    if (isWhitespace(character)) continue;

    if (character === "\"") {
      beginString(index);
    } else if (character === "[") {
      beginContainer("array");
    } else if (character === "{") {
      beginContainer("object");
    } else if (character === "]") {
      closeContainer("array");
    } else if (character === "}") {
      closeContainer("object");
    } else if (character === ":") {
      const container = currentContainer();
      if (!container || container.type !== "object" || container.state !== "colon") {
        fail("has malformed JSON object structure");
      }
      container.state = "value";
    } else if (character === ",") {
      const container = currentContainer();
      if (!container || container.state !== "commaOrEnd") {
        fail("has misplaced comma in JSON structure");
      }
      container.state = container.type === "array" ? "value" : "key";
    } else {
      beginValue();
      while (index + 1 < contents.length && !isWhitespace(contents[index + 1]) &&
             contents[index + 1] !== "," && contents[index + 1] !== "]" &&
             contents[index + 1] !== "}" && contents[index + 1] !== ":") {
        index++;
      }
    }
  }

  if (inString || containers.length > 0 || rootState !== "end") {
    fail("has unclosed containers or truncated JSON structure");
  }

  return JSON.parse(contents);
}

function readFileWithinLimit(filePath, targetRoot) {
  const resolvedTarget = path.resolve(targetRoot);
  const resolvedFile = path.resolve(filePath);

  if (resolvedFile !== resolvedTarget &&
      !resolvedFile.startsWith(resolvedTarget + path.sep)) {
    throw new SafeInputError("file path escapes authorized target scope");
  }

  if (HAS_SAFE_INPUT_OPEN) {
    const noFollow = fs.constants.O_NOFOLLOW;
    const nonBlock = fs.constants.O_NONBLOCK;
    let descriptor;
    try {
      descriptor = fs.openSync(resolvedFile, fs.constants.O_RDONLY | noFollow | nonBlock);
    } catch (error) {
      if (error && (error.code === "ELOOP" || error.code === "EMLINK")) {
        throw new SafeInputError("input must not be an unconfined symlink");
      }
      throw error;
    }
    try {
      const stat = fs.fstatSync(descriptor);
      if (!stat.isFile()) throw new SafeInputError("input must be a regular file");
      if (stat.size > LIMITS.inputBytes) throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);

      const chunks = [];
      const buffer = Buffer.allocUnsafe(64 * 1024);
      let bytesRead = 0;
      while (true) {
        const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
        if (count === 0) break;
        bytesRead += count;
        if (bytesRead > LIMITS.inputBytes) {
          throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);
        }
        chunks.push(Buffer.from(buffer.subarray(0, count)));
      }
      try {
        return UTF8_DECODER.decode(Buffer.concat(chunks, bytesRead));
      } catch {
        throw new SafeInputError("input is not valid UTF-8");
      }
    } finally {
      fs.closeSync(descriptor);
    }
  } else {
    // Windows or non-POSIX safe input read fallback
    let lstat;
    try {
      lstat = fs.lstatSync(resolvedFile);
    } catch (error) {
      throw new SafeInputError(`unable to stat file: ${error.message}`);
    }
    if (lstat.isSymbolicLink()) {
      let real;
      try {
        real = fs.realpathSync(resolvedFile);
      } catch (error) {
        throw new SafeInputError(`unable to resolve symlink: ${error.message}`);
      }
      if (real !== resolvedTarget && !real.startsWith(resolvedTarget + path.sep)) {
        throw new SafeInputError("symlink target escapes authorized audit scope");
      }
    }
    const stat = fs.statSync(resolvedFile);
    if (!stat.isFile()) throw new SafeInputError("input must be a regular file");
    if (stat.size > LIMITS.inputBytes) throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);

    let buffer;
    try {
      buffer = fs.readFileSync(resolvedFile);
    } catch (error) {
      throw new SafeInputError(`read error: ${error.message}`);
    }
    if (buffer.length > LIMITS.inputBytes) throw new SafeInputError(`input exceeds ${LIMITS.inputBytes} byte limit`);
    try {
      return UTF8_DECODER.decode(buffer);
    } catch {
      throw new SafeInputError("input is not valid UTF-8");
    }
  }
}

function walkDirectoryConfined(targetDir, options = {}) {
  const resolvedTarget = path.resolve(targetDir);
  const files = [];
  const limitations = [];
  let fileCount = 0;

  function traverse(currentDir, depth) {
    if (depth > LIMITS.maxDepth) {
      limitations.push({
        path: normalizeRelativePath(path.relative(resolvedTarget, currentDir)),
        reason: `traversal depth exceeded ${LIMITS.maxDepth} limit`,
      });
      return;
    }
    if (fileCount >= LIMITS.maxFiles) {
      return;
    }

    let entries;
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (error) {
      limitations.push({
        path: normalizeRelativePath(path.relative(resolvedTarget, currentDir)),
        reason: `cannot read directory: ${error.message}`,
      });
      return;
    }

    for (const entry of entries) {
      if (fileCount >= LIMITS.maxFiles) {
        limitations.push({
          path: normalizeRelativePath(path.relative(resolvedTarget, currentDir)),
          reason: `file inventory cap reached (${LIMITS.maxFiles} files)`,
        });
        break;
      }

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isSymbolicLink()) {
        let real;
        try {
          real = fs.realpathSync(fullPath);
        } catch (error) {
          limitations.push({
            path: normalizeRelativePath(path.relative(resolvedTarget, fullPath)),
            reason: `broken or inaccessible symlink: ${error.message}`,
          });
          continue;
        }
        if (real !== resolvedTarget && !real.startsWith(resolvedTarget + path.sep)) {
          limitations.push({
            path: normalizeRelativePath(path.relative(resolvedTarget, fullPath)),
            reason: "symlink escapes target scope",
          });
          continue;
        }
        let stat;
        try {
          stat = fs.statSync(real);
        } catch (error) {
          limitations.push({
            path: normalizeRelativePath(path.relative(resolvedTarget, fullPath)),
            reason: `symlink target stat error: ${error.message}`,
          });
          continue;
        }
        if (stat.isDirectory()) {
          traverse(fullPath, depth + 1);
        } else if (stat.isFile()) {
          fileCount++;
          files.push(fullPath);
        }
      } else if (entry.isDirectory()) {
        traverse(fullPath, depth + 1);
      } else if (entry.isFile()) {
        fileCount++;
        files.push(fullPath);
      }
    }
  }

  traverse(resolvedTarget, 0);
  return { files, limitations };
}

function resolveSharedRoot(packageDir, targetRoot) {
  let current = path.dirname(packageDir);
  const resolvedTarget = path.resolve(targetRoot);

  while (current.startsWith(resolvedTarget)) {
    const candidate = path.join(current, "_shared");
    if (fs.existsSync(candidate) && fs.statSync(candidate).isDirectory()) {
      return candidate;
    }
    if (current === resolvedTarget) break;
    current = path.dirname(current);
  }

  // Default fallback is _shared at target root if present
  const targetShared = path.join(resolvedTarget, "_shared");
  if (fs.existsSync(targetShared) && fs.statSync(targetShared).isDirectory()) {
    return targetShared;
  }
  return null;
}

function inspectAisopOrAisp(fullPath, targetRoot, isNativeAisp) {
  const resolvedTarget = path.resolve(targetRoot);
  const relativeFile = normalizeRelativePath(path.relative(resolvedTarget, fullPath));
  const observations = [];
  const limitations = [];

  let contents;
  try {
    contents = readFileWithinLimit(fullPath, targetRoot);
  } catch (error) {
    const reason = error instanceof SafeInputError ? error.message : "file read failed";
    limitations.push({
      file: relativeFile,
      reason,
      format: isNativeAisp ? "native_aisp" : "standalone_aisop",
    });
    return { item: null, observations, limitations };
  }

  let doc;
  try {
    doc = preflightAndParseJsonText(contents);
  } catch (error) {
    const reason = error instanceof JsonStructureError ? error.message : "invalid JSON";
    limitations.push({
      file: relativeFile,
      reason,
      format: isNativeAisp ? "native_aisp" : "standalone_aisop",
    });
    return { item: null, observations, limitations };
  }

  if (!Array.isArray(doc) || doc.length !== 2) {
    limitations.push({
      file: relativeFile,
      reason: "program shape must be a two-element JSON array [system, user]",
      format: isNativeAisp ? "native_aisp" : "standalone_aisop",
    });
    return { item: null, observations, limitations };
  }

  const [systemMsg, userMsg] = doc;
  if (!isObject(systemMsg) || systemMsg.role !== "system" || !isObject(systemMsg.content) ||
      !isObject(userMsg) || userMsg.role !== "user" || !isObject(userMsg.content)) {
    limitations.push({
      file: relativeFile,
      reason: "program shape requires system message followed by user message",
      format: isNativeAisp ? "native_aisp" : "standalone_aisop",
    });
    return { item: null, observations, limitations };
  }

  const sysContent = systemMsg.content;
  const userContent = userMsg.content;

  const standardSysKeys = new Set([
    "protocol", "axiom_0", "id", "name", "version", "license",
    "summary", "flow_format", "loading_mode", "tools", "params", "system_prompt",
  ]);
  const unknownSysKeys = Object.keys(sysContent).filter((key) => !standardSysKeys.has(key));

  const standardUserKeys = new Set(["instruction", "aisop", "functions", "aisp_contract"]);
  const unknownUserKeys = Object.keys(userContent).filter((key) => !standardUserKeys.has(key));

  const functions = isObject(userContent.functions) ? userContent.functions : {};
  const nodes = Object.keys(functions);
  const dispatchedSteps = [];
  const advisoryConstraints = [];

  for (const [nodeName, nodeDef] of Object.entries(functions)) {
    if (!isObject(nodeDef)) continue;
    for (const [key, value] of Object.entries(nodeDef)) {
      if (/^step\d+$/.test(key) && typeof value === "string") {
        dispatchedSteps.push({
          node: nodeName,
          step: key,
          operation: value,
          execute_mode: nodeDef.execute_mode || "inline",
        });
      }
    }
    if (Array.isArray(nodeDef.constraints)) {
      for (const constraint of nodeDef.constraints) {
        if (typeof constraint === "string") {
          advisoryConstraints.push({
            node: nodeName,
            text: constraint,
          });
        }
      }
    }
  }

  if (!isNativeAisp) {
    // Standalone AISOP program
    const item = {
      type: "standalone_aisop",
      id: typeof sysContent.id === "string" ? sysContent.id : path.basename(fullPath, ".aisop.json"),
      name: typeof sysContent.name === "string" ? sysContent.name : null,
      protocol: typeof sysContent.protocol === "string" ? sysContent.protocol : null,
      version: typeof sysContent.version === "string" ? sysContent.version : null,
      file: relativeFile,
      flow_format: sysContent.flow_format || null,
      loading_mode: sysContent.loading_mode || null,
      tools: Array.isArray(sysContent.tools) ? sysContent.tools : [],
      entry_flow: userContent.aisop && userContent.aisop.main ? userContent.aisop.main : null,
      nodes,
      dispatched_steps: dispatchedSteps,
      advisory_constraints: advisoryConstraints,
      unknown_extension_fields: [...unknownSysKeys.map((k) => `system.${k}`), ...unknownUserKeys.map((k) => `user.${k}`)],
    };
    return { item, observations, limitations };
  }

  // Native AISP package
  const packageDir = path.dirname(fullPath);
  const relativePackageDir = normalizeRelativePath(path.relative(resolvedTarget, packageDir));

  if (sysContent.loading_mode !== "node") {
    observations.push({
      file: relativeFile,
      rule: "conformance",
      observation: `Native AISP requires loading_mode: "node", got ${safeQuote(sysContent.loading_mode)}.`,
    });
  }

  const contract = isObject(userContent.aisp_contract) ? userContent.aisp_contract : null;
  if (!contract) {
    limitations.push({
      file: relativeFile,
      reason: "Native AISP package is missing required user.content.aisp_contract object",
      format: "native_aisp",
    });
    return { item: null, observations, limitations };
  }

  const standardContractKeys = new Set(["profile", "invocation", "non_negotiable", "discovery", "risk_level", "resources"]);
  const unknownContractKeys = Object.keys(contract).filter((key) => !standardContractKeys.has(key));

  // Bridge detection
  let bridgeFile = null;
  const bridgeSkill = path.join(packageDir, "SKILL.md");
  const bridgeReadme = path.join(packageDir, "README.md");
  if (fs.existsSync(bridgeSkill) && fs.statSync(bridgeSkill).isFile()) {
    bridgeFile = normalizeRelativePath(path.relative(resolvedTarget, bridgeSkill));
  } else if (fs.existsSync(bridgeReadme) && fs.statSync(bridgeReadme).isFile()) {
    bridgeFile = normalizeRelativePath(path.relative(resolvedTarget, bridgeReadme));
  }

  // Cross-reference bindings in non_negotiable
  const bindings = [];
  if (Array.isArray(contract.non_negotiable)) {
    for (const ruleEntry of contract.non_negotiable) {
      if (!isObject(ruleEntry)) continue;
      const { rule, enforced_by } = ruleEntry;
      if (typeof enforced_by !== "string") continue;

      const bindingMatch = enforced_by.match(/^([a-zA-Z0-9_-]+)\.([a-zA-Z0-9_-]+)(?::(.*))?$/);
      if (bindingMatch) {
        const [, targetNode, targetStep, mechanism] = bindingMatch;
        const nodeObj = functions[targetNode];
        const stepExists = nodeObj && typeof nodeObj[targetStep] === "string";

        if (!nodeObj) {
          observations.push({
            file: relativeFile,
            binding: enforced_by,
            rule: rule || null,
            observation: `The rule references ${enforced_by}, but node ${safeQuote(targetNode)} does not exist in functions.`,
          });
        } else if (!stepExists) {
          const availableSteps = Object.keys(nodeObj).filter((k) => /^step\d+$/.test(k)).sort();
          const stepSummary = availableSteps.length > 0
            ? `${availableSteps[0]} through ${availableSteps[availableSteps.length - 1]}`
            : "no steps";
          observations.push({
            file: relativeFile,
            binding: enforced_by,
            rule: rule || null,
            observation: `The confirmation rule references ${enforced_by}, but functions.${targetNode} has only ${stepSummary}.`,
          });
        }

        bindings.push({
          rule,
          enforced_by,
          target_node: targetNode,
          target_step: targetStep,
          mechanism: mechanism || null,
          resolves: Boolean(stepExists),
        });
      } else {
        bindings.push({
          rule,
          enforced_by,
          target_node: null,
          target_step: null,
          mechanism: enforced_by,
          resolves: null,
        });
      }
    }
  }

  // Declared resources inspection
  const declaredResources = [];
  if (Array.isArray(contract.resources)) {
    const sharedRoot = resolveSharedRoot(packageDir, resolvedTarget);

    for (const res of contract.resources) {
      if (!isObject(res) || typeof res.path !== "string") continue;

      const scope = res.scope === "shared" ? "shared" : "skill";
      let resolvedResPath = null;
      let inScope = true;
      let exists = false;
      let error = null;

      if (scope === "skill") {
        resolvedResPath = path.resolve(packageDir, res.path);
        if (resolvedResPath !== resolvedTarget && !resolvedResPath.startsWith(resolvedTarget + path.sep)) {
          inScope = false;
          error = "resource path escapes authorized audit scope";
        }
      } else {
        if (!sharedRoot) {
          error = "shared scope resource declared but no _shared root directory found in scope";
          inScope = false;
        } else {
          resolvedResPath = path.resolve(sharedRoot, res.path);
          if (resolvedResPath !== resolvedTarget && !resolvedResPath.startsWith(resolvedTarget + path.sep)) {
            inScope = false;
            error = "shared resource escapes authorized audit scope";
          }
        }
      }

      if (inScope && resolvedResPath) {
        try {
          exists = fs.existsSync(resolvedResPath) && fs.statSync(resolvedResPath).isFile();
        } catch {
          exists = false;
        }
      }

      declaredResources.push({
        id: res.id || null,
        declared_path: res.path,
        resolved_path: resolvedResPath && inScope ? normalizeRelativePath(path.relative(resolvedTarget, resolvedResPath)) : null,
        scope,
        kind: res.kind || null,
        mode: res.mode || null,
        exists,
        in_scope: inScope,
        error,
      });
    }
  }

  const item = {
    type: "native_aisp",
    id: typeof sysContent.id === "string" ? sysContent.id : path.basename(packageDir),
    name: typeof sysContent.name === "string" ? sysContent.name : null,
    protocol: typeof sysContent.protocol === "string" ? sysContent.protocol : null,
    version: typeof sysContent.version === "string" ? sysContent.version : null,
    license: typeof sysContent.license === "string" ? sysContent.license : null,
    package_dir: relativePackageDir,
    entry_file: relativeFile,
    bridge_file: bridgeFile,
    flow_format: sysContent.flow_format || null,
    loading_mode: sysContent.loading_mode || null,
    tools: Array.isArray(sysContent.tools) ? sysContent.tools : [],
    contract: {
      profile: contract.profile || null,
      invocation: contract.invocation || null,
      discovery: contract.discovery || null,
      risk_level: contract.risk_level || null,
    },
    entry_flow: userContent.aisop && userContent.aisop.main ? userContent.aisop.main : null,
    nodes,
    dispatched_steps: dispatchedSteps,
    advisory_constraints: advisoryConstraints,
    bindings,
    declared_resources: declaredResources,
    unknown_extension_fields: [
      ...unknownSysKeys.map((k) => `system.${k}`),
      ...unknownUserKeys.map((k) => `user.${k}`),
      ...unknownContractKeys.map((k) => `contract.${k}`),
    ],
  };

  return { item, observations, limitations };
}

function discoverAisp(targetDir, options = {}) {
  const resolvedTarget = path.resolve(targetDir);
  if (!fs.existsSync(resolvedTarget)) {
    throw new SafeInputError(`target directory does not exist: ${resolvedTarget}`);
  }
  const stat = fs.statSync(resolvedTarget);
  if (!stat.isDirectory()) {
    throw new SafeInputError(`target is not a directory: ${resolvedTarget}`);
  }

  const { files, limitations: walkLimitations } = walkDirectoryConfined(resolvedTarget, options);

  const packages = [];
  const standalonePrograms = [];
  const structuralObservations = [];
  const allLimitations = [...walkLimitations];

  for (const filePath of files) {
    const filename = path.basename(filePath);
    if (!filename.endsWith(".aisop.json")) continue;

    const parentDir = path.dirname(filePath);
    const parentBasename = path.basename(parentDir);
    const isNativeAisp = filename === "aisp.aisop.json" && parentBasename.endsWith("_aisp");

    const result = inspectAisopOrAisp(filePath, resolvedTarget, isNativeAisp);
    structuralObservations.push(...result.observations);
    allLimitations.push(...result.limitations);

    if (result.item) {
      if (result.item.type === "native_aisp") {
        packages.push(result.item);
      } else {
        standalonePrograms.push(result.item);
      }
    }
  }

  // Sort deterministically
  packages.sort((a, b) => a.entry_file.localeCompare(b.entry_file));
  standalonePrograms.sort((a, b) => a.file.localeCompare(b.file));
  structuralObservations.sort((a, b) => a.file.localeCompare(b.file));
  allLimitations.sort((a, b) => (a.file || a.path || "").localeCompare(b.file || b.path || ""));

  return {
    target: normalizeRelativePath(path.relative(process.cwd(), resolvedTarget)) || ".",
    packages,
    standalone_programs: standalonePrograms,
    structural_observations: structuralObservations.slice(0, LIMITS.maxObservations),
    limitations: allLimitations.slice(0, LIMITS.maxLimitations),
    summary: {
      packages_count: packages.length,
      standalone_count: standalonePrograms.length,
      observations_count: structuralObservations.length,
      limitations_count: allLimitations.length,
    },
  };
}

function run(args) {
  const targetDir = args[0];
  if (!targetDir || args.includes("--help") || args.includes("-h")) {
    console.error("Usage: node discover-aisp.cjs <target-directory>");
    return 1;
  }

  try {
    const result = discoverAisp(targetDir);
    console.log(JSON.stringify(result, null, 2));
    return 0;
  } catch (error) {
    const reason = error instanceof SafeInputError
      ? escapeUnsafeDiagnosticCharacters(error.message)
      : "unexpected discovery error";
    console.error(`Failed to discover AISOP/AISP: ${reason}`);
    return 1;
  }
}

module.exports = {
  LIMITS,
  JsonStructureError,
  SafeInputError,
  discoverAisp,
  escapeUnsafeDiagnosticCharacters,
  inspectAisopOrAisp,
  preflightAndParseJsonText,
  readFileWithinLimit,
  safeQuote,
};

if (require.main === module) {
  process.exit(run(process.argv.slice(2)));
}
