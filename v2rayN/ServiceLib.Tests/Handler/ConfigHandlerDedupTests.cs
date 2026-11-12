using ServiceLib.Tests.CoreConfig;

namespace ServiceLib.Tests.Handler;

[NotInParallel]
public class ConfigHandlerDedupTests
{
    private static ProfileItem Profile(string name = "Original")
    {
        var profile = new ProfileItem
        {
            ConfigType = EConfigType.VLESS,
            Remarks = name,
            Address = "edge.example.com",
            Port = 443,
            Password = "11111111-1111-4111-8111-111111111111",
            Network = "ws",
            StreamSecurity = Global.StreamSecurity,
            Sni = "origin.example.com",
        };
        profile.SetProtocolExtra(new ProtocolExtraItem { VlessEncryption = "none" });
        profile.SetTransportExtra(new TransportExtraItem { Host = "origin.example.com", Path = "/ws?ed=2560" });
        return profile;
    }

    private static Config Config(ECoreType core = ECoreType.Xray, string? fingerprint = "chrome")
    {
        var config = CoreConfigTestFactory.CreateConfig();
        config.CoreBasicItem.DefFingerprint = fingerprint;
        config.CoreTypeItem = [new CoreTypeItem { ConfigType = EConfigType.VLESS, CoreType = core }];
        config.GuiItem.KeepOlderDedupl = true;
        return config;
    }

    private static async Task AssertPair(Config config, ProfileItem first, ProfileItem second, bool duplicate)
    {
        CoreConfigTestFactory.BindAppManagerConfig(config);
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        var sub = $"dedup-{Guid.NewGuid():N}";
        first.Subid = second.Subid = sub;
        first.IndexId = Guid.NewGuid().ToString("N");
        second.IndexId = Guid.NewGuid().ToString("N");
        await SQLiteHelper.Instance.ReplaceAsync(first);
        await SQLiteHelper.Instance.ReplaceAsync(second);
        var beforeFirst = JsonUtils.Serialize(first, false);
        var beforeSecond = JsonUtils.Serialize(second, false);

        var (total, remaining) = await ConfigHandler.DedupServerList(config, sub);

        await total.Should().BeEqualTo(2);
        await remaining.Should().BeEqualTo(duplicate ? 1 : 2);
        var stored = (await AppManager.Instance.ProfileItems(sub))!;
        await stored.Count.Should().BeEqualTo(remaining);
        foreach (var profile in stored)
        {
            await JsonUtils.Serialize(profile, false).Should()
                .BeEqualTo(profile.IndexId == first.IndexId ? beforeFirst : beforeSecond);
        }
        await ConfigHandler.RemoveServersViaSubid(config, sub, false);
    }

    [Test]
    [Arguments(ECoreType.Xray, "chrome", null, "chrome", true)]
    [Arguments(ECoreType.Xray, "firefox", null, "chrome", false)]
    [Arguments(ECoreType.Xray, "chrome", "chrome", "unsafe", false)]
    [Arguments(ECoreType.sing_box, "chrome", null, "chrome", false)]
    [Arguments(ECoreType.sing_box, "chrome", null, "unsafe", true)]
    [Arguments(ECoreType.sing_box, "chrome", "hellochrome_120", "chrome", true)]
    public async Task FingerprintsFollowTheSelectedCore(ECoreType core, string defaultFingerprint,
        string? firstFingerprint, string? secondFingerprint, bool duplicate)
    {
        var first = Profile();
        var second = Profile("Different name");
        first.Fingerprint = firstFingerprint;
        second.Fingerprint = secondFingerprint;
        await AssertPair(Config(core, defaultFingerprint), first, second, duplicate);
    }

    [Test]
    public async Task ExplicitCoreOverridesTheConfiguredDefault()
    {
        var first = Profile();
        var second = Profile("Copy");
        first.CoreType = second.CoreType = ECoreType.sing_box;
        second.Fingerprint = "chrome";
        await AssertPair(Config(), first, second, false);
    }

    [Test]
    public async Task DifferentEffectiveCoresRemainSeparate()
    {
        var first = Profile();
        var second = Profile("Copy");
        first.CoreType = ECoreType.Xray;
        second.CoreType = ECoreType.sing_box;
        first.Fingerprint = second.Fingerprint = "chrome";
        await AssertPair(Config(), first, second, false);
    }

    [Test]
    [Arguments(ECoreType.Xray, "ws", true)]
    [Arguments(ECoreType.Xray, "httpupgrade", true)]
    [Arguments(ECoreType.Xray, "grpc", false)]
    [Arguments(ECoreType.sing_box, "ws", false)]
    public async Task AlpnDefaultsAreSpecificToTheCoreAndTransport(ECoreType core, string network, bool duplicate)
    {
        var first = Profile();
        var second = Profile("Copy");
        first.Network = second.Network = network;
        second.Alpn = "http/1.1";
        await AssertPair(Config(core), first, second, duplicate);
    }

    [Test]
    public async Task DomainsIgnoreCaseWithoutRewritingStoredValues()
    {
        var first = Profile();
        var second = Profile("Copy");
        second.Address = first.Address.ToUpperInvariant();
        second.Sni = first.Sni.ToUpperInvariant();
        second.SetTransportExtra(second.GetTransportExtra() with { Host = "ORIGIN.EXAMPLE.COM" });
        await AssertPair(Config(), first, second, true);
    }

    [Test]
    public async Task AuthorityHostnamesIgnoreCaseAndPreserveThePort()
    {
        var first = Profile();
        var second = Profile("Copy");
        first.Network = second.Network = "grpc";
        first.SetTransportExtra(new TransportExtraItem { GrpcAuthority = "origin.example.com:443", GrpcServiceName = "Service" });
        second.SetTransportExtra(new TransportExtraItem { GrpcAuthority = "ORIGIN.EXAMPLE.COM:443", GrpcServiceName = "Service" });
        await AssertPair(Config(), first, second, true);
        second.SetTransportExtra(second.GetTransportExtra() with { GrpcAuthority = "origin.example.com:8443" });
        await AssertPair(Config(), first, second, false);
    }

    [Test]
    [Arguments("password")]
    [Arguments("port")]
    [Arguments("sni")]
    [Arguments("path")]
    [Arguments("query")]
    [Arguments("early-data")]
    [Arguments("security")]
    [Arguments("insecure")]
    [Arguments("cipher")]
    [Arguments("certificate")]
    [Arguments("transport-extra")]
    [Arguments("protocol-extra")]
    public async Task MeaningfulDifferencesAreNeverRemoved(string field)
    {
        var first = Profile();
        var second = Profile("Copy");
        switch (field)
        {
            case "password": first.Password = "Token"; second.Password = "token"; break;
            case "port": second.Port = 8443; break;
            case "sni": second.Sni = "another.example.com"; break;
            case "path": second.SetTransportExtra(second.GetTransportExtra() with { Path = "/WS?ed=2560" }); break;
            case "query": second.SetTransportExtra(second.GetTransportExtra() with { Path = "/ws?ed=2560&advert=Channel" }); break;
            case "early-data": second.SetTransportExtra(second.GetTransportExtra() with { Path = "/ws?ed=512" }); break;
            case "security": second.StreamSecurity = ""; break;
            case "insecure": second.AllowInsecure = Global.StringTrue; break;
            case "cipher": second.CipherSuites = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"; break;
            case "certificate": second.CertSha = "different-certificate"; break;
            case "transport-extra": second.SetTransportExtra(second.GetTransportExtra() with { XdriveSecrets = "different-secret" }); break;
            case "protocol-extra": second.SetProtocolExtra(second.GetProtocolExtra() with { Flow = "xtls-rprx-vision" }); break;
        }
        await AssertPair(Config(), first, second, false);
    }

    [Test]
    public async Task FingerprintAndAlpnWithoutTlsDoNotCreateDifferentConnections()
    {
        var first = Profile();
        var second = Profile("Copy");
        first.StreamSecurity = second.StreamSecurity = "";
        second.Fingerprint = "chrome";
        second.Alpn = "http/1.1";
        await AssertPair(Config(), first, second, true);
    }

    [Test]
    public async Task TrojanWithAndWithoutTlsIsNotADuplicate()
    {
        var first = Profile();
        var second = Profile("Copy");
        first.ConfigType = second.ConfigType = EConfigType.Trojan;
        second.StreamSecurity = "";
        await AssertPair(Config(), first, second, false);
    }

    [Test]
    public async Task EquivalentExtraJsonFormattingDoesNotMatter()
    {
        var first = Profile();
        var second = Profile("Copy");
        second.TransportExtra = "{\"Path\":\"/ws?ed=2560\",\"Host\":\"origin.example.com\"}";
        // Use a fresh instance so the raw JSON, rather than the earlier cached record, is read.
        second = JsonUtils.Deserialize<ProfileItem>(JsonUtils.Serialize(second, false))!;
        await AssertPair(Config(), first, second, true);
    }

    [Test]
    [Arguments("{broken")]
    [Arguments("{\"NewConnectionSetting\":\"different\",\"VlessEncryption\":\"none\"}")]
    [Arguments("{\"VlessEncryption\":42}")]
    [Arguments("{\"VlessEncryption\":\"none\",\"Future\":null}")]
    [Arguments("{\"VlessEncryption\":\"none\",\"Future\":\"\"}")]
    [Arguments("{\"VlessEncryption\":\"none\",\"Future\":{\"Value\":null}}")]
    public async Task UnrecognizedExtraDataIsPreserved(string extra)
    {
        var first = Profile();
        var second = Profile("Copy");
        second.ProtoExtra = extra;
        second = JsonUtils.Deserialize<ProfileItem>(JsonUtils.Serialize(second, false))!;
        await AssertPair(Config(), first, second, false);
    }

    [Test]
    [Arguments("127.1")]
    [Arguments("2130706433")]
    [Arguments("0x7f000001")]
    public async Task LegacyNumericHostnamesAreNotRewrittenAsIpAddresses(string host)
    {
        var first = Profile();
        var second = Profile("Copy");
        first.Address = "127.0.0.1";
        second.Address = host;
        await AssertPair(Config(), first, second, false);
    }
}
