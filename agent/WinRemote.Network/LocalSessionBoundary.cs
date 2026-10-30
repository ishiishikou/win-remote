namespace WinRemote.Network;

/// <summary>
/// Pure limits for a future authenticated single-user session. All times are
/// monotonic ages computed by a trusted in-process clock, not browser values.
/// This does not authenticate, register a device, or create an actual session.
/// </summary>
internal static class LocalSessionBoundary
{
    internal enum Capability { Read, Input, Shell, Screen }

    internal sealed record MonotonicSnapshot(
        TimeSpan SessionAge,
        TimeSpan SinceLastHumanAction,
        bool SessionRevoked,
        bool PcLocallyApprovedShell,
        bool PcLocallyApprovedScreen,
        TimeSpan? PrivilegeWindowAge,
        TimeSpan? ReauthAgeWhenWindowOpened);

    internal sealed record Decision(bool Allowed, string Reason)
    {
        internal static Decision Deny(string reason) => new(false, reason);
    }

    private static readonly TimeSpan MaxSessionAge = TimeSpan.FromHours(8);
    private static readonly TimeSpan MaxIdle = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan MaxPrivilegeAge = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan ReauthFreshnessAtElevation = TimeSpan.FromMinutes(5);

    internal static Decision Evaluate(MonotonicSnapshot? state, Capability requested)
    {
        if (state is null || state.SessionRevoked)
            return Decision.Deny("session_revoked_or_missing");

        // Require monotonic, not DateTime.Now. Clock rollback, resume, loss of
        // process state or inability to compute ages must revoke the session.
        if (state.SessionAge < TimeSpan.Zero ||
            state.SinceLastHumanAction < TimeSpan.Zero ||
            state.SinceLastHumanAction > state.SessionAge ||
            state.SessionAge >= MaxSessionAge)
            return Decision.Deny("session_expired_or_invalid_clock");

        if (state.SinceLastHumanAction >= MaxIdle)
            return Decision.Deny("idle_session_expired");

        if (requested is Capability.Read or Capability.Input)
            return new Decision(true, "normal_session_only");

        if (requested is not (Capability.Shell or Capability.Screen))
            return Decision.Deny("unknown_capability");

        if ((requested == Capability.Shell && !state.PcLocallyApprovedShell) ||
            (requested == Capability.Screen && !state.PcLocallyApprovedScreen))
            return Decision.Deny("pc_feature_not_approved");

        if (state.PrivilegeWindowAge is not { } privilegedAge ||
            state.ReauthAgeWhenWindowOpened is not { } reauthAtOpening ||
            privilegedAge < TimeSpan.Zero ||
            privilegedAge > state.SessionAge ||
            privilegedAge >= MaxPrivilegeAge ||
            reauthAtOpening < TimeSpan.Zero ||
            reauthAtOpening > ReauthFreshnessAtElevation)
            return Decision.Deny("privileged_window_expired_or_invalid");

        return new Decision(true, "privileged_window_only");
    }
}
