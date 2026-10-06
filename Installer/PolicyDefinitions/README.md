# OpenAccess EID - Group Policy Templates

This directory contains the ADMX / ADML files that expose the **custom**
OpenAccess EID policies in the Group Policy Editor (`gpedit.msc`) and
the domain Group Policy Management Console (GPMC).

## Files

- `OpenAccessEID.admx` - policy definitions
- `en-US/OpenAccessEID.adml` - English display strings

## Scope

Only policies introduced by this product are defined here. The smart-card
policies that the product also consumes (for example `AllowSignatureOnlyKeys`,
`AllowIntegratedUnblock`, `FilterDuplicateCertificates`, and so on) are
standard Windows policies already defined in the Microsoft-supplied
`SmartCard.admx` that ships with Windows, and can be configured through that
template. All policies are read from the same registry hive:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows\SmartCardCredentialProvider
```

## Deployment

### Local machine
The NSIS installer copies these files to:

- `%WINDIR%\PolicyDefinitions\OpenAccessEID.admx`
- `%WINDIR%\PolicyDefinitions\en-US\OpenAccessEID.adml`

They then appear under:
`Computer Configuration \ Administrative Templates \ Windows Components \ OpenAccess EID`

### Domain (Group Policy Central Store)
For domain deployment, copy the files to the PolicyDefinitions central store
on a domain controller:

```
\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\OpenAccessEID.admx
\\<domain>\SYSVOL\<domain>\Policies\PolicyDefinitions\en-US\OpenAccessEID.adml
```

Once replicated, every GPMC console in the domain picks up the template
automatically - no per-admin-workstation install is required.

## Policies defined

| Policy | Registry value | Default |
|--------|---------------|---------|
| Enforce CSP whitelist | `EnforceCSPWhitelist` (DWORD) | `0` (Disabled) |
| Hold back the card's last PIN attempts until it is re-inserted | `PinAttemptsReserved` (DWORD, 0-10; 0 = off) | `1` |

`EnforceCSPWhitelist` is the security-critical addition - when enabled it
blocks smart-card certificates that use a CSP / KSP provider outside the
built-in whitelist, mitigating attacker-controlled cryptographic provider
substitution.
