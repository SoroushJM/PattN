# Remove duplicate

The desktop command checks every profile in the current subscription, or all profiles in the All view. Row selection and the search filter do not limit its scope. It keeps one member of each duplicate set according to the existing Keep older duplicates preference. This uses database enumeration order, not the visible table's sort order. Custom configurations, custom outbounds, policy groups, and proxy chains are excluded.

## Connection identity

Names, subscription metadata, internal IDs, and display logging preferences are not connection settings. Removal compares the selected core and the profile's connection settings, including complete typed protocol and transport extras and TLS/certificate options. It does not use the looser subscription-update matching rules.

Known equivalents are normalized for comparison only; surviving profiles are not rewritten:

- DNS hostnames in the destination, SNI, transport Host, and gRPC authority ignore letter case. An authority's port remains significant. Paths, query strings, credentials, and arbitrary header values retain their case and content.
- An unspecified network uses the profile's effective default network.
- For VMess, VLESS, and Trojan using Xray TLS/Reality, an absent fingerprint uses the configured default fingerprint. It matches explicit `chrome` only when the default is `chrome`.
- For those protocols using sing-box, absent and `unsafe` fingerprints use plain TLS; explicit `chrome` uses uTLS. `hellochrome_120` maps to sing-box's `chrome`, as in the outbound builder.
- With the Xray fork's WebSocket/HTTPUpgrade TLS transport, absent ALPN and explicit `http/1.1` are equivalent. This rule is not applied to other cores or transports.
- Without TLS, the fingerprint and ALPN are inactive for these protocols. TLS and no-TLS profiles still remain distinct, including Trojan.
- Empty and null known string settings are equivalent. Unrecognized extra fields and malformed extra data remain part of the identity to avoid discarding potentially different settings.

The comparison is conservative. It does not probe servers, resolve DNS to merge different addresses, strip advertising from WebSocket paths, or infer that different ports reach the same service. It does not claim to recognize every possible core-specific equivalence. Changing the default fingerprint or selected core can change which profiles are equivalent; identities are rebuilt on each invocation.

## Regression checks

Run from the repository root with the configured .NET 10 SDK:

```sh
dotnet test --project v2rayN/ServiceLib.Tests/ServiceLib.Tests.csproj -c Release
```

`ConfigHandlerDedupTests` covers core-specific defaults, DNS letter case, preservation of paths/credentials/security differences, unrecognized data, and unchanged surviving records. Existing Aether deduplication tests cover its protocol-specific settings.
