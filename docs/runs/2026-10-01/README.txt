The recorded run of 1 October 2026
==================================

This directory holds one real run of Canary's v1 demo. On 1 October 2026,
scripts/demo-regtest.sh --act5 ran against Bitcoin Core v31.1.0 in regtest
mode, with canary 0.1.0 built from commit 3a1417f. Block 351 held five
taproot payments. The withholding server left the 1 BTC payment,
ad56b9bb...e21e, out of its served list while signing it into its record.
canary check over blocks 0 to 351 gave 351 Checked and 1 Data withheld, and
named that server. In act 5, block 201, checked with the withholder alone,
reads Can't be checked, reason gap_unfilled. Records came over HTTP from each
server. Nothing went to Nostr relays.

Everything here is what the script wrote, except the edits listed below.


See it yourself
---------------

From the repository root:

    go run ./cmd/canary status --state docs/runs/2026-10-01/state.json
    go run ./cmd/canary verify docs/runs/2026-10-01/evidence/omission-regtest-351-ad56b9bb-db614560.json
    go run ./cmd/canary ui --state docs/runs/2026-10-01/state.json

The dashboard's finding 79ec3cb71656 shows the evidence file checking out.
The dashboard reads a relative evidence_dir against the state file's own
directory, so this works from any clone. It will say the results are old,
because the run finished on 1 October.

Don't point canary check at these state files. It would overwrite them.


What each file is
-----------------

run.txt
    The run's facts: the payment's txid, its block, Core's tip, each server's
    address and pubkey, and the evidence file's name. With act 5, the early
    payment and its block too.

demo-regtest-output.txt
    Everything scripts/demo-regtest.sh --act5 printed, from the prerequisite
    check to stopping bitcoind.

check.txt
    What canary check printed for blocks 0 to 351, with both servers pinned
    and the payment declared.

verify.txt
    What canary verify printed for the evidence file. It checks out.

status.txt
    What canary status printed for state.json.

state.json
    The state file canary check wrote for blocks 0 to 351.

evidence/omission-regtest-351-ad56b9bb-db614560.json
    The evidence file canary check wrote for the one finding. It is
    byte-identical to evidence/omission-regtest-351-ad56b9bb-db614560.json at
    the repository root: 2,722 bytes, SHA-256
    aea26b9bf54926af62eefe09b7fb7bd64540025b052001f52a41f77cac1b9710.

logs/honest.log, logs/withholder.log
    Each reference indexer's log. They hold public keys only. The secret keys
    lived in a temporary directory the script removed on exit.

act5/check.txt, act5/status.txt
    What the act 5 canary check, on block 201 alone with only the withholder
    pinned, and its canary status printed.

act5/state.json
    The state file of the act 5 check: one block, Can't be checked.

README.txt
    This file. It is plain text because the site publishes only .json, .txt
    and .log files from a run.


What was changed from the raw output, and why
---------------------------------------------

The script makes its output directory an absolute path, so the raw files
named the build machine's home directory. Those paths exist on no other
computer, and they name a person's account. Each was cut down as follows.
Nothing else in any file was changed.

state.json, line 21
    Raw: "evidence_dir": "<absolute path of the output directory>/evidence"
    Now: "evidence_dir": "evidence"
    The first commit of this run, 2679bc4, had "demo-out/evidence" here. That
    path is relative to the working directory, so it found nothing in a
    clone. "evidence" names the copy of the evidence file in this directory,
    and canary ui reads it against the state file's directory.

act5/state.json, line 21
    Raw: "evidence_dir": "<absolute path of the output directory>/act5/evidence"
    Now: "evidence_dir": "evidence"
    Act 5 found nothing, so it wrote no evidence file, and act5/evidence does
    not exist. The value follows the same rule as state.json's, so neither
    state file names a path on the build machine.

check.txt, line 6
    Raw: Results saved to <absolute path of the output directory>/state.json.
    Now: Results saved to demo-out/state.json.

act5/check.txt, line 4
    Raw: Results saved to <absolute path of the output directory>/act5/state.json.
    Now: Results saved to demo-out/act5/state.json.

demo-regtest-output.txt, lines 4, 46, 74, 82 to 87 and 89
    Each absolute path of the output directory was cut to demo-out, the path
    the script wrote to, relative to the repository root. On line 85, the
    repository's own absolute path became <local path>.

evidence/omission-regtest-351-ad56b9bb-db614560.json
    Added. A copy of the file canary check wrote, so the state file's
    evidence_dir names a directory that exists in every clone.

README.txt
    Added. This file.
