"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const vm = require("node:vm");

const appPath = path.join(__dirname, "app.js");
const appSource = fs.readFileSync(appPath, "utf8");
const functionStart = appSource.indexOf("function enrollmentCommand(platform) {");
const functionEnd = appSource.indexOf("\nfunction stopEnrollmentTimer()", functionStart);

assert.notEqual(functionStart, -1, "enrollmentCommand must remain present in app.js");
assert.notEqual(functionEnd, -1, "enrollmentCommand must have a stable function boundary");

const enrollmentFunctionSource = appSource.slice(functionStart, functionEnd);

function windowsCommand(sha256) {
  const context = vm.createContext({
    command: null,
    preferredInstaller(platform) {
      assert.equal(platform, "WINDOWS");
      return { sha256 };
    }
  });
  vm.runInContext(
    `${enrollmentFunctionSource}\ncommand = enrollmentCommand("WINDOWS");`,
    context,
    { filename: appPath }
  );
  return context.command;
}

test("Windows enrollment setup is complete, ordered, and does not embed the grant", () => {
  const digest = "a".repeat(64);
  const command = windowsCommand(digest);

  assert.equal(typeof command, "string");
  assert.match(command, /\$ErrorActionPreference = 'Stop'/);
  assert.match(command, /WindowsBuiltInRole\]::Administrator/);
  assert.match(command, new RegExp(`\\$expectedScannerSha256 = '${digest}'`));
  assert.match(command, /Get-FileHash -LiteralPath \$scannerExe -Algorithm SHA256/);
  assert.match(command, /environment = 'development'/);
  assert.match(command, /base_url = 'http:\/\/127\.0\.0\.1:8080'/);
  assert.match(command, /allow_insecure_loopback_http = \$true/);
  assert.match(command, /offload_vulnerability_analysis = \$true/);
  assert.match(command, /health --config \$scannerConfig/);
  assert.match(command, /Read-Host .* -AsSecureString/);
  assert.match(command, /SecureStringToBSTR/);
  assert.match(command, /Remove-Item Env:\\SCANNER_ENROLLMENT_TOKEN/);
  assert.match(command, /ZeroFreeBSTR/);
  assert.match(command, /Set-Clipboard -Value \(\[string\]::Empty\)/);
  assert.match(command, /enroll --config \$scannerConfig/);
  assert.match(command, /agent --config \$scannerConfig --endpoint-id \$endpointId/);
  assert.doesNotMatch(command, /<paste/i);
  assert.doesNotMatch(enrollmentFunctionSource, /state\.enrollmentGrant|grant\.enrollment_token/);

  const healthAt = command.indexOf("health --config");
  const promptAt = command.indexOf("Read-Host");
  const enrollAt = command.indexOf("enroll --config");
  const cleanupAt = command.indexOf("Remove-Item Env:\\SCANNER_ENROLLMENT_TOKEN");
  const agentAt = command.indexOf("agent --config");
  assert.ok(healthAt < promptAt, "health validation must precede token entry");
  assert.ok(promptAt < enrollAt, "the hidden token prompt must precede enrollment");
  assert.ok(enrollAt < cleanupAt, "the token must be cleaned after the enrollment process exits");
  assert.ok(cleanupAt < agentAt, "the long-running agent must start only after token cleanup");
});

test("untrusted installer metadata cannot inject PowerShell", () => {
  const command = windowsCommand("a'; Write-Output 'injected'");

  assert.match(command, /A trusted scanner SHA-256 is unavailable/);
  assert.doesNotMatch(command, /Write-Output 'injected'/);
  assert.doesNotMatch(command, /\$expectedScannerSha256/);
});

const powerShell = process.platform === "win32" ? "powershell.exe" : "pwsh";
const powerShellProbe = spawnSync(powerShell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"], {
  encoding: "utf8"
});

test("generated Windows setup parses in PowerShell", { skip: Boolean(powerShellProbe.error) }, () => {
  const command = windowsCommand("b".repeat(64));
  const parserScript = [
    "$source = [Console]::In.ReadToEnd()",
    "$tokens = $null",
    "$errors = $null",
    "[System.Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$errors) | Out-Null",
    "if ($errors.Count -gt 0) { $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }; exit 1 }"
  ].join("; ");
  const parsed = spawnSync(
    powerShell,
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", parserScript],
    { input: command, encoding: "utf8" }
  );

  assert.equal(parsed.status, 0, parsed.stderr || "PowerShell parser rejected the setup command");
});
