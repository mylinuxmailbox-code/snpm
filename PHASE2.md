# Phase 2 additions

## Mandatory 12-hour quarantine

Resolution first computes the normal semver candidate list, newest first. The quarantine selector then walks only that list and accepts the first release whose registry `time[version]` is at least 12 hours old and not in the future. It never searches outside the requested range.

`fried_chicken ^2.0.0` with `2.1.0` at 3 hours and `2.0.9` at 2 days resolves to `2.0.9`. `fried_chicken ^2.1.0` has no eligible candidate because `2.0.9` is outside the range, so it throws `QuarantineViolationError`. Missing or invalid publication times fail closed. The rule is selection policy, not a warning or preference.

## Platform policy

The runtime keeps platform decisions behind small adapters: Linux and macOS have configurable ClamAV Unix-socket candidates, Windows has no Unix-socket default and must receive a configured named pipe or TCP endpoint in the scanner layer. Signal handling exposes SIGINT everywhere and SIGTERM only where portable. Hermetic state remains under `.snpm`; no home-directory cache is used.

The matrix tests run the quarantine semantics for Linux, macOS and Windows targets even when CI itself is one OS.
