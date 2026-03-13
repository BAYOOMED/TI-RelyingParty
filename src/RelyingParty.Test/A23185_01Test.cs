namespace RelyingParty.Test;

[TestClass]
public class A23185_01Test
{
    /// <summary>
    ///     A_23185-01 - Key created today should be accepted (within 398 days).
    /// </summary>
    [TestMethod]
    public void A23185_01_FreshKeyId_IsAccepted()
    {
        var keyId = Guid.CreateVersion7();
        Assert.AreEqual(7, keyId.Version);
        var createdAt = GetUuid7Timestamp(keyId);
        var age = DateTimeOffset.UtcNow - createdAt;
        Assert.IsTrue(age.TotalDays < 398);
    }

    /// <summary>
    ///     A_23185-01 - Key created 400 days ago should be detectable as expired.
    /// </summary>
    [TestMethod]
    public void A23185_01_ExpiredKeyId_IsDetected()
    {
        var oldTimestamp = DateTimeOffset.UtcNow.AddDays(-400);
        var oldKeyId = Guid.CreateVersion7(oldTimestamp);
        var createdAt = GetUuid7Timestamp(oldKeyId);
        var age = DateTimeOffset.UtcNow - createdAt;
        Assert.IsTrue(age.TotalDays > 398, "key older than 398 days should be detected");
    }

    /// <summary>
    ///     A_23185-01 - Key created 380 days ago should trigger warning zone (within 30 days of limit).
    /// </summary>
    [TestMethod]
    public void A23185_01_SoonExpiredKeyId_IsInWarningZone()
    {
        var nearLimitTimestamp = DateTimeOffset.UtcNow.AddDays(-380);
        var keyId = Guid.CreateVersion7(nearLimitTimestamp);
        var createdAt = GetUuid7Timestamp(keyId);
        var age = DateTimeOffset.UtcNow - createdAt;
        Assert.IsTrue(age.TotalDays > 368, "should be in warning zone (> 398 - 30 days)");
        Assert.IsTrue(age.TotalDays < 398, "should not yet be expired");
    }
    
    private static DateTimeOffset GetUuid7Timestamp(Guid uuid)
    {
        Span<byte> bytes = stackalloc byte[16];
        uuid.TryWriteBytes(bytes, bigEndian: true, out _);
        long unixMs = ((long)bytes[0] << 40) | ((long)bytes[1] << 32) | ((long)bytes[2] << 24) |
                      ((long)bytes[3] << 16) | ((long)bytes[4] << 8) | bytes[5];
        return DateTimeOffset.FromUnixTimeMilliseconds(unixMs);
    }
}
