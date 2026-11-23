"""Project only the three reviewed late-ready blocks for historical whole-broker proofs.

The runnable profile-permission-ui gate uses the actual unmodified source.
"""
from hashlib import sha256


def digest(value):
    return sha256(value.encode()).hexdigest()


def predecessor(text):
    baseline = "f21aa2b52ecb77b253db4b6a0edb421e4554ff1f83779c7e7bd5f8a0eb9ea888"
    candidate = "a855ce737251e86f33a9bc849f07c5342edfe238a1c15f6ca79494883856aeba"
    if digest(text) == baseline:
        return text, {"applied": False, "source_sha256": baseline}
    from pathlib import Path
    from runpy import run_path
    exact = run_path(str(Path(__file__).resolve().parents[1]/"notes-task-info-reader/first_root_history.py"))
    text = exact["predecessor"]("BackgroundDisplayBroker.java", text)
    if digest(text) != candidate:
        raise RuntimeError("Unreviewed late-ready broker source")
    blocks = [
        (
            '    private volatile String profilePreparationState=',
            '    private volatile java.util.Map<Integer,String> permissionPhysicalBaseline;',
            "579dee4f21fdef48ff14981a8dfb81242a9740d1ce65e0add22c5a8da75f1178",
            """    private volatile String profilePreparationState="NOT_STARTED";
""",
        ),
        (
            '            } else if(config.profileTarget!=null&&"prepare_done".equals(r.operation)) {',
            '            } else if(config.profileTarget!=null&&"launch".equals(r.operation)) {',
            "71ad0f58d1538a1c4173c064528b9aed573880d9a513a82e8e04155fa00531ae",
            """            } else if(config.profileTarget!=null&&"prepare_done".equals(r.operation)) {
                requirePermissionPreparing(r);
                if(!"APP_READY".equals(profileOwnedTask.initializationState(Math.min(r.deadline,expires))))
                    throw new BrokerProtocol.Refusal("PROFILE_PERMISSION_SETUP_REQUIRED");
                requirePermissionPhysicalUnchanged(permissionPhysicalFence(r));
                if(!profileOwnedTask.confirmInitializationReady(Math.min(r.deadline,expires)))throw new BrokerProtocol.Refusal("PROFILE_TASK_NOT_OBSERVED");
                profilePreparing=false;profilePreparationState="COMPLETE";refreshProfileTaskEvidence();
""",
        ),
        (
            '            value.put("profile_permission_preparing",profilePreparing)',
            '            PermissionWindowObservation permission=permissionWindow;',
            "34a8b951df2326de5e8cad4b10eaf2c0623df902845bcfd3a6da3db59852c7ca",
            """            value.put("profile_permission_preparing",profilePreparing).put("profile_permission_preparation_state",profilePreparationState);
""",
        ),
    ]
    for start, end, expected, original in blocks:
        first = text.index(start)
        last = text.index(end, first + len(start))
        if digest(text[first:last]) != expected:
            raise RuntimeError("Reviewed late-ready block differs")
        text = text[:first] + original + text[last:]
    if digest(text) != baseline:
        raise RuntimeError("R31 whole-broker proof differs")
    return text, {"applied": True, "source_sha256": candidate, "r31_sha256": baseline, "blocks": len(blocks)}
