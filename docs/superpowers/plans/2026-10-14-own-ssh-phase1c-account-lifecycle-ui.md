# Records account lifecycle UI

## Scope and authorization

Implement the approved native leave/rotation contracts in the existing records workspace. The user authorized autonomous implementation. Frontend files and dedicated documentation only; other agents own native integration. Preserve their work. Do not execute real account operations.

## Contracts and behavior

- Leave returns a durable receipt plus public overview. Require explicit acknowledgment that selected space hosts become Local copies with remapped IDs/jumps, local credentials remain local, and remote sources remain retained.
- Rotation returns the existing account setup shape, including new words and explicit completion/pending error. Require acknowledgment: retained source chains are frozen, the old code reads historical data, future updates use the new code, and devices rejoin with the new code.
- Codes stay in component state; direct IPC only. Cache only public overview. No query/mutation cache, logging, clipboard, or persistent browser storage for codes.
- Pending leave/rotation uses existing account resume. Show pending receipts honestly; closing or clearing UI does not undo durable work.
- Migration resume accepts optional recovery words directly; retain on failure, clear on success/cancel.
- Startup visibility already calls Rust window.show before engine initialization when not starting hidden. No frontend show hook is needed.

## TDD and validation

1. RED: direct contract, consent refusal, partial outcomes, component-only code, error privacy, optional migration recovery; SSR consent/outcome tests.
2. GREEN: typed clients, pure actions, focused lifecycle component and AccountPanel integration.
3. Focused records Vitest, TypeScript, then production build for root native smoke. Exact owned paths only in serialized conventional commit.
