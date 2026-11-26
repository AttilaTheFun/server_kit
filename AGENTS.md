# For agents: Server Kit

Read `README.md` first: what each library is for.

- **Public.** No names of people, no private hosts, addresses, team ids or tokens in code, comments, tests or docs.
- **Every library stands alone:** depend on another only where its types are needed. `NetworkCore` depends on nothing
  and `PairingLink` on `NetworkCore` alone, and neither imports Foundation; keep it so.
- **Linux and Apple's systems alike:** anything Apple-only behind `#if canImport(…)`, and its library says so.
- **Security first.** Pins are compared in constant time, codes and tokens are kept as SHA-256s and never logged, and
  an address with the server's own certificate goes nowhere without a pin. Changes to any of these need a test that
  says why.
- **Every pull request adds `changes/<branch>.md`** (`changes/README.md`), never edits a changelog by hand.
- **Releases** are proposed as drafts with their proof, and published by the code owner.
