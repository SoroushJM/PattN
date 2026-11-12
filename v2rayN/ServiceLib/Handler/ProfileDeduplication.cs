namespace ServiceLib.Handler;

/// <summary>
/// An identity for removal, separate from subscription-update matching. Normalization is deliberately
/// conservative: only known runtime equivalents are merged, without modifying the stored profiles.
/// </summary>
internal static class ProfileDeduplication
{
    public static string Identity(Config config, ProfileItem profile)
    {
        var core = profile.CoreType
            ?? config.CoreTypeItem?.FirstOrDefault(item => item.ConfigType == profile.ConfigType)?.CoreType
            ?? ECoreType.Xray;
        var network = profile.GetNetwork();
        var security = profile.StreamSecurity;
        var fingerprint = profile.Fingerprint;
        var alpn = profile.Alpn;
        // Other protocols can provide TLS themselves, so do not infer their defaults here.
        if (profile.ConfigType is EConfigType.VLESS or EConfigType.VMess or EConfigType.Trojan)
        {
            var tls = security is Global.StreamSecurity or Global.StreamSecurityReality;
            if (!tls)
            {
                fingerprint = alpn = string.Empty;
            }
            else if (core == ECoreType.Xray)
            {
                fingerprint = string.IsNullOrEmpty(fingerprint) ? config.CoreBasicItem.DefFingerprint : fingerprint;
                // The Xray fork offers HTTP/1.1 for an unspecified WebSocket/HTTPUpgrade ALPN.
                if (security == Global.StreamSecurity && network is "ws" or "httpupgrade"
                    && (profile.GetAlpn() is null or []))
                {
                    alpn = "http/1.1";
                }
            }
            else if (core == ECoreType.sing_box)
            {
                // sing-box enables uTLS only for an explicit fingerprint other than unsafe.
                fingerprint = fingerprint switch
                {
                    "unsafe" => string.Empty,
                    "hellochrome_120" => "chrome",
                    _ => fingerprint,
                };
            }
        }

        var transport = profile.GetTransportExtra() with
        {
            Host = Host(profile.GetTransportExtra().Host),
            GrpcAuthority = Host(profile.GetTransportExtra().GrpcAuthority),
        };
        var identity = new JsonObject
        {
            ["ConfigType"] = (int)profile.ConfigType,
            ["Core"] = (int)core,
            ["PreSocksPort"] = profile.PreSocksPort,
            ["Address"] = Host(profile.Address),
            ["Port"] = profile.Port,
            ["Password"] = profile.Password,
            ["Username"] = profile.Username,
            ["Network"] = network,
            ["StreamSecurity"] = security,
            ["AllowInsecure"] = profile.GetAllowInsecure(),
            ["Sni"] = Host(profile.Sni),
            ["Alpn"] = alpn,
            ["Fingerprint"] = fingerprint,
            ["CipherSuites"] = profile.CipherSuites,
            ["CurvePreferences"] = profile.CurvePreferences,
            ["EnableSessionResumption"] = profile.EnableSessionResumption,
            ["DialMode"] = profile.DialMode,
            ["TargetStrategy"] = profile.GetTargetStrategy(),
            ["PublicKey"] = profile.PublicKey,
            ["ShortId"] = profile.ShortId,
            ["SpiderX"] = profile.SpiderX,
            ["Mldsa65Verify"] = profile.Mldsa65Verify,
            ["MuxEnabled"] = profile.MuxEnabled,
            ["Cert"] = profile.Cert,
            ["CertSha"] = profile.CertSha,
            ["EchConfigList"] = profile.EchConfigList,
            ["EchOutbound"] = profile.EchOutbound,
            ["VerifyPeerCertByName"] = profile.VerifyPeerCertByName,
            ["Finalmask"] = profile.Finalmask,
            ["Protocol"] = Extra(profile.ProtoExtra, profile.GetProtocolExtra()),
            ["Transport"] = Extra(profile.TransportExtra, transport),
        };
        return Canonical(identity)!.ToJsonString();
    }

    private static JsonNode? Extra<T>(string? raw, T extra) where T : class
    {
        var normalized = JsonUtils.ParseJson(JsonUtils.Serialize(extra, false, true))!.AsObject();
        var unknown = new JsonObject();
        if (!string.IsNullOrEmpty(raw))
        {
            // Preserve malformed or future fields instead of silently discarding them through typed parsing.
            try
            {
                if (JsonUtils.Deserialize<T>(raw) is null
                    || JsonNode.Parse(raw, documentOptions: new JsonDocumentOptions { CommentHandling = JsonCommentHandling.Skip }) is not JsonObject original)
                {
                    return JsonValue.Create(raw);
                }
                var known = new HashSet<string>(normalized.Select(property => property.Key), StringComparer.OrdinalIgnoreCase);
                foreach (var property in original)
                {
                    if (!known.Contains(property.Key))
                    {
                        unknown[property.Key] = property.Value?.DeepClone();
                    }
                }
            }
            catch (JsonException)
            {
                return JsonValue.Create(raw);
            }
        }
        // An opaque canonical string keeps unknown subtrees out of the known-field default normalization.
        return JsonValue.Create(new JsonObject
        {
            ["Settings"] = Canonical(normalized),
            ["Unknown"] = Canonical(unknown, omitEmpty: false),
        }.ToJsonString());
    }

    private static JsonNode? Canonical(JsonNode? value, bool omitEmpty = true)
    {
        if (value is JsonObject obj)
        {
            var result = new JsonObject();
            foreach (var property in obj.OrderBy(property => property.Key, StringComparer.Ordinal))
            {
                if (omitEmpty && (property.Value is null
                    || property.Value is JsonValue scalar && scalar.TryGetValue<string>(out var text) && text == ""))
                {
                    continue;
                }
                result[property.Key] = Canonical(property.Value, omitEmpty);
            }
            return result;
        }
        if (value is JsonArray array)
        {
            return new JsonArray(array.Select(item => Canonical(item, omitEmpty)).ToArray());
        }
        return value?.DeepClone();
    }

    private static string? Host(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }
        if (Uri.CheckHostName(value) == UriHostNameType.Dns)
        {
            return value.ToLowerInvariant();
        }
        // HTTP Host and gRPC authority can include a port; never lowercase a path or arbitrary header value.
        var colon = value.LastIndexOf(':');
        if (colon > 0 && int.TryParse(value[(colon + 1)..], out _)
            && Uri.CheckHostName(value[..colon]) == UriHostNameType.Dns)
        {
            return value[..colon].ToLowerInvariant() + value[colon..];
        }
        return value;
    }
}
