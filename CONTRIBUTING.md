# Contributing to SYM

SYM is the reference Node.js implementation of the [Mesh Memory Protocol (MMP)](https://sym.bot/spec/mmp). All changes must comply with the specification.

## Branch Strategy

- **`main`** is protected. No direct pushes.
- Create feature branches from `main` (e.g. `feat/uuid-v7`, `fix/heartbeat-timeout`).
- Submit a pull request. All PRs require at least one review and passing CI before merge.

## Before Submitting a PR

1. **Read the spec.** If your change touches identity, transport, connection, memory, coupling, or any protocol layer, verify it conforms to [MMP](https://sym.bot/spec/mmp).
2. **Run tests.** All tests must pass:
   ```bash
   npm test
   ```
3. **Test on Node 18+.** The minimum supported version is Node.js 18.
4. **Keep commits focused.** One logical change per commit. Reference MMP spec sections where applicable.

## Development Setup

```bash
git clone https://github.com/sym-bot/sym.git
cd sym
npm install
npm test
```

## Code Style

- Match existing patterns. No unnecessary abstractions.
- Production quality: proper error handling, no shortcuts.
- Only add comments where logic isn't self-evident.
- Prefer simplicity. Three similar lines are better than a premature abstraction.

## Spec Changes

If you believe the MMP spec itself should change, open an issue describing the proposed change and rationale before implementing. Spec changes require separate review at [symbot-website](https://github.com/sym-bot/symbot-website).
