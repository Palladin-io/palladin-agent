import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8');

describe('Windows hardened packaging contract', () => {
  it('declares a fixed packaged LocalService broker and restricted capability', () => {
    const manifest = read('packaging/windows/manifests/Palladin.Broker.appxmanifest.in');
    expect(manifest).toContain('Name="Palladin.Runtime.Broker"');
    expect(manifest).toContain('Name="PalladinRuntime"');
    expect(manifest).toContain('StartAccount="localService"');
    expect(manifest).toContain('Name="packagedServices"');
    expect(manifest).toContain('Executable="bin\\palladin-service.exe"');
    expect(manifest).not.toContain('StartAccount="localSystem"');
  });

  it('keeps the companion in AppContainer without full-trust capability', () => {
    const manifest = read('packaging/windows/manifests/Palladin.Companion.appxmanifest.in');
    expect(manifest).toContain('uap10:TrustLevel="appContainer"');
    expect(manifest).toContain('uap10:RuntimeBehavior="packagedClassicApp"');
    expect(manifest).not.toContain('runFullTrust');
    expect(manifest).toContain('Category="windows.appExecutionAlias"');
    expect(manifest).toContain('Alias="palladin-runtime-companion.exe"');
  });

  it('forbids downgrade in both App Installer and the signed update script', () => {
    const appInstaller = read('packaging/windows/manifests/Palladin.Runtime.appinstaller.in');
    expect(appInstaller).toContain('<ForceUpdateFromAnyVersion>false</ForceUpdateFromAnyVersion>');
    const update = read('packaging/windows/scripts/Update-SecureRuntime.ps1');
    expect(update).toContain('Assert-PalladinVersionPolicy');
    expect(update).not.toContain('ForceUpdateFromAnyVersion');
  });

  it('requires Authenticode publisher, thumbprint, and RFC3161 timestamps before staging npm', () => {
    const stage = read('packaging/windows/scripts/Stage-NpmPlatformPackage.ps1');
    expect(stage).toContain('Assert-PalladinSignature');
    expect(stage).toContain('-RequireTimestamp');
    expect(stage).toContain("foreach ($field in 'scripts', 'dependencies', 'optionalDependencies')");
  });

  it('builds a one-UAC administrator bootstrapper with embedded installer components', () => {
    const manifest = read('packaging/windows/bootstrapper/app.manifest');
    const source = read('packaging/windows/bootstrapper/Program.cs.in');
    expect(manifest).toContain('level="requireAdministrator"');
    expect(source).toContain('PowerShellPayload');
    expect(source).toContain('GetManifestResourceStream');
    expect(source).toContain('Environment.SpecialFolder.ProgramFiles');
    expect(source).toContain('EnsureNotReparse');
    expect(source).toContain('"/inheritance:r"');
    expect(source).toContain('"*S-1-5-18:(OI)(CI)F"');
  });

  it('packages worker with broker and produces x64 plus arm64 bundles', () => {
    const build = read('packaging/windows/scripts/Build-Msix.ps1');
    const bundle = read('packaging/windows/scripts/Build-MsixBundle.ps1');
    expect(build).toContain("'bin/palladin-worker.exe'");
    expect(bundle).toContain("'x64 MSIX'");
    expect(bundle).toContain("'arm64 MSIX'");
  });

  it('compiles the broker with the exact publisher-derived Companion PFN', () => {
    const broker = read('runtime/crates/palladin-windows-broker/src/windows.rs');
    const release = read('packaging/windows/scripts/Palladin.Release.psm1');
    const workflow = read('.github/workflows/windows-signed-runtime.yml');
    expect(broker).toContain('option_env!("PALLADIN_WINDOWS_PACKAGE_FAMILY_NAME")');
    expect(release).toContain('PackageFamilyNameFromId');
    expect(workflow).toContain('PALLADIN_WINDOWS_PACKAGE_FAMILY_NAME: ${{ vars.PALLADIN_WINDOWS_COMPANION_PFN }}');
    expect(workflow).toContain('Get-PalladinPackageFamilyName');
    expect(workflow).toContain("if ($derivedPfn -cne $env:PALLADIN_WINDOWS_PACKAGE_FAMILY_NAME)");
  });

  it('keeps signing owner-only and stages the CLI as the fixed worker', () => {
    const pullRequest = read('.github/workflows/rust-runtime.yml');
    const signed = read('.github/workflows/windows-signed-runtime.yml');
    expect(signed).toContain("if: github.actor == 'patryk-roguszewski'");
    expect(signed).toContain('environment: windows-signing');
    expect(signed).toContain("Copy-Item -LiteralPath (Join-Path $source 'palladin.exe') -Destination (Join-Path $source 'palladin-worker.exe')");
    expect(pullRequest).toContain("-Destination './target/${{ matrix.target }}/release/palladin-worker.exe'");
  });
});
