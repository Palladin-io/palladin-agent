import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

const read = (path: string): string => readFileSync(path, 'utf8');

describe('Windows hardened packaging contract', () => {
  it('declares a fixed packaged LocalService broker and restricted capability', () => {
    const manifest = read('packaging/windows/manifests/Palladin.Broker.appxmanifest.in');
    expect(manifest).toContain('Name="Palladin.Runtime.Broker"');
    expect(manifest).toContain('Name="PalladinRuntime"');
    expect(manifest).toContain('StartupType="auto"');
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

  it('creates canonical ProgramData top-down with no-follow handles and exact native ACLs', () => {
    const install = read('packaging/windows/scripts/Install-SecureRuntime.ps1');
    const update = read('packaging/windows/scripts/Update-SecureRuntime.ps1');
    const release = read('packaging/windows/scripts/Palladin.Release.psm1');
    expect(install).not.toContain('$env:ProgramData');
    expect(update).not.toContain('$env:ProgramData');
    expect(release).toContain('62AB5D82-FDC1-4DC3-A9DD-070D1D495D97');
    expect(release).toContain('SHGetKnownFolderPath');
    expect(release).toContain('CharSet = CharSet.Unicode, ExactSpelling = true');
    expect(release).toContain('FileFlagOpenReparsePoint');
    expect(release).toContain('CreateDirectoryW');
    expect(release).toContain('SetSecurityInfo');
    expect(release).toContain('GetSecurityInfo');
    expect(release).toContain('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)');
    expect(release).toContain('String.Equals(actual, expected, StringComparison.Ordinal)');
    expect(release).not.toContain('?? throw');
    expect(release).not.toContain('Set-Acl -LiteralPath $Path');
    expect(update).not.toContain('Set-Acl');
    expect(update).toContain('New-PalladinProtectedUpdateStage');
    const exported = release.split('\n').find((line) => line.startsWith('Export-ModuleMember -Function')) ?? '';
    for (const helper of [
      'Get-PalladinCanonicalProgramDataRoot',
      'Initialize-PalladinBootstrapDataRoot',
      'Initialize-PalladinProtectedDataRoot',
      'Assert-PalladinProtectedDataRoot',
      'New-PalladinProtectedUpdateStage',
    ]) {
      expect(exported).toContain(helper);
    }
  });

  it('provisions deny-by-default ProgramData before auto service registration and verifies update before activation', () => {
    const install = read('packaging/windows/scripts/Install-SecureRuntime.ps1');
    const update = read('packaging/windows/scripts/Update-SecureRuntime.ps1');
    expect(install.indexOf('Initialize-PalladinBootstrapDataRoot')).toBeLessThan(
      install.indexOf('Add-AppxPackage -Path $BrokerPackage'),
    );
    expect(install.indexOf('$existingService = Get-Service')).toBeLessThan(
      install.indexOf('Initialize-PalladinBootstrapDataRoot'),
    );
    expect(install.indexOf('Assert-PalladinProtectedDataRoot -ServiceSid $existingServiceSid')).toBeLessThan(
      install.indexOf('Add-AppxPackage -Path $BrokerPackage'),
    );
    expect(install).toContain("if ($null -eq $existingService) {");
    expect(install).toContain('PalladinRuntime service SID changed during repair');
    expect(install.indexOf('Initialize-PalladinProtectedDataRoot')).toBeGreaterThan(
      install.indexOf('sidtype PalladinRuntime restricted'),
    );
    expect(install).toContain('Start-Service -Name PalladinRuntime');
    expect(update.indexOf('Assert-PalladinProtectedDataRoot')).toBeLessThan(
      update.indexOf('Add-AppxPackage -Path $stagedBroker'),
    );
    expect(update.match(/Assert-PalladinProtectedDataRoot/g)).toHaveLength(2);
    expect(update.indexOf('Assert-PalladinProtectedDataRoot', update.indexOf('Add-AppxPackage'))).toBeLessThan(
      update.indexOf('Start-Service -Name PalladinRuntime'),
    );
  });

  it('bounds broker connections and reports rejection causes to the user', () => {
    const service = read('runtime/crates/palladin-windows-broker/src/bin/service.rs');
    const companion = read('runtime/crates/palladin-windows-broker/src/companion.rs');
    expect(service).toContain('Semaphore::new(MAX_ACTIVE_CONNECTIONS)');
    expect(service).toContain('timeout(INITIAL_FRAME_TIMEOUT');
    expect(service).toContain('timeout(CONSENT_FRAME_TIMEOUT');
    expect(companion).toContain('return Err(rejection_error(*code))');
    expect(companion).toContain('Windows Hello consent expired; retry the command');
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
