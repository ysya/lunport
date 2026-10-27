# Catalog conflicts keep both devices' changes — design

2026-10-27. Follow-up R70 of the Connect via design (`2026-10-26-iap-connect-via-design.md`); it replaces that design's "Conflicts" paragraph ("one whole version is kept … There is no new conflict UI"). Branch `claude/stoic-snyder-8c0e08`, built on `claude/google-tunnel-ui-design-c3a057` (PR #93, merged here as `f6a5ff56`). Frank decided the open questions and accepted the calls on 2026-10-27, through the Connect via session.

Words: the **Catalog** is the library's one shared metadata record `meta/catalog` (`central/payload.rs:167`), holding collections, group orders, tunnel rules and routes. An **item** is one entry of it (defined below). The **common version** is the Catalog this device's change was made on, **this device's version** is the one it wants to publish, and the **synced version** is the library's current one. A **collision** is an item both devices changed, to different values.

## Intent

Two devices that both change the Catalog inside one pull-to-push window race for one record. The relay accepts the first push and refuses the second because it expected an older revision (`relay/src/v2/store.ts:1784`, 409 `revision_conflict` at `:1823`). The refused round fails: the status reads "Sync interrupted · Changes saved locally" and sync waits at least 90 seconds (`round.rs:158-166`, `relay.rs:65-69`). The next round reads the first device's Catalog, the capture holds this device's change against the older basis, and that becomes a conflict (`replica.rs:625-637`, `projection_capture.rs:112-134`). Central conflicts offers only "Keep this device's version" for it (`conflicts.rs:149`; `public_remote` refuses `meta` at `:167`), which publishes this device's whole Catalog over the other device's: its collections, group order, tunnels and routes are gone from the library, and the next projection on the other device removes them there too. A route the publish step moved into the library (R64a) has no copy left on its device, so it is lost.

The Catalog bundles four independent lists into one record only because the record format does. Hosts do not have this problem: two devices editing two different hosts never conflict, because each host is its own record. This design gives the Catalog the same behaviour item by item: changes to different items from two devices are combined without asking, and only two changes to the same item ask the person, in plain words.

Success: Frank adds a tunnel on one computer and an IAP route on the other within the same sync window. Both computers end with both. The refused computer combines them in the same round, and neither a review nor a sync error appears. When both computers change the same tunnel, Central conflicts shows that tunnel, its two versions in plain words and two buttons; whichever he picks, every other change from both computers stays.

## Goals

1. Changes to different items of the Catalog from two devices both survive a race, with no question asked.
2. When both devices changed the same item differently, the person chooses, seeing the items and their two versions in plain words; nothing else is lost by the choice.
3. The merged Catalog never exceeds what one record holds. What does not fit is said plainly; a route this device added that does not fit keeps working on this device.
4. A two-device test proves the race no longer loses either device's routes or tunnels.

## Non-goals

- Merging fields inside one item (two edits of one tunnel or one route).
- Any change to the relay, the wire format or the Catalog's shape and limits.
- Any change to how conflicts of hosts, groups, keys and saved passwords are reviewed.
- A choice per colliding item, or keeping both versions of a tunnel.
- A notice that an automatic merge happened.
- Changing older releases: a device on a release without this design keeps today's behaviour when it meets a Catalog conflict.

## Anti-goals

- Losing either device's routes, tunnels, collections or group order to a Catalog conflict.
- Asking about changes that do not touch the same item.
- Dropping anything silently because it does not fit.
- A merged Catalog that the library refuses, or that stops the library syncing.
- Combining two edits of one item into a value neither device saved, such as a route pointing at an instance that does not exist in its project.
- A keychain prompt raised by background sync.

## Constraints

- One record, unchanged: `Catalog` is `deny_unknown_fields`, and `Catalog::validate` (`payload.rs:185`) allows at most 256 routes (`MAX_ROUTES`), 256 tunnels, 256 collections, 257 group orders and 4096 ordered groups. The encoded record must fit `MAX_PLAINTEXT_BYTES` (64 KiB, `catalog_fits`, `payload.rs:397`); a Catalog that does not fit fails the whole capture.
- The conflict already holds what a merge needs. The replica keeps the synced version (`replica.current`), this device's draft (`replica.pending[..].latest`), and its basis (`projection_capture::basis_of`, `projection_capture.rs:18`: the device's own last confirmed write, else the version its rows last read). All three are signed, encrypted versions that open as the review opens them (`conflicts.rs:60-76`).
- A conflict can be retired only once the refused write can no longer commit (`conflicts::settled`, `conflicts.rs:88`): no claimed receipt, and any sent draft expected a revision older than the current one.
- Background sync never creates the recovery archive's key: doing so can raise an OS prompt, which the archive code avoids (`replacement_archive.rs:380`).
- Writes follow the library's gates, as the publish step does (`active_dispatch.rs:286-299`): none while the library's writes are blocked or it is frozen for an encrypted migration.
- New tests use synthetic values only (e.g. `acme-dev-654321`, `frank@example.com`), never real project ids or accounts.

## How it works (decided)

### Items and the rule

The Catalog's items:

- a **tunnel rule**, keyed by its rule id; its value is the whole rule (`TunnelRule`);
- a **route**, keyed by its host id; its value is the whole route (`HostTransport`, as the Catalog holds it, without a justification);
- a **collection**, keyed by its id; its value is its name;
- a **group order**, keyed by its scope; its value is its group ids in order. Under central sync, only the library-wide order (the Local scope, `group_order::set`, account row `library-group-order`) is edited. A collection's own order passes through from the Catalog the device read (`projection_cache.rs:152-153`), so in practice only the Local order can collide.

For every item key found in any of the three versions, with *c*, *t* and *s* its value in the common version, this device's version and the synced version (an absent item is a value too):

- *t* = *c*: the synced value *s* (this device did not touch it);
- *s* = *c*: this device's value *t*;
- *t* = *s*: that value (both made the same change);
- otherwise, a **collision**.

Adding and removing an item are changes like any other, so "removed here, edited there" is a collision, and "removed on both" is not. Values compare as decoded values; the order of a list inside the Catalog is not part of an item, except the ids of a group order. The merged Catalog's order is the one the capture gives: the order of the Catalog the device read, then new items by id (`catalog_of`, `projection_local.rs:137`).

The three versions:

- **Common**: the Catalog at `basis_of`, opened and verified.
- **This device's**: the Catalog this device's rows hold now, as the capture would publish it (`catalog_of` over the rows, with the ledger's Catalog as `original`). An edit not yet captured is merged, never overwritten. Once captured, this equals the pending draft.
- **Synced**: the replica's current Catalog.

### A refused push

When the relay refuses a push because a record's expected revision is no longer current, the round pulls again at once instead of failing (`active_cycle::with_budget`, `active_cycle.rs:100-109`). The relay answers 409 `revision_conflict` and refuses the whole batch (`store.ts:1822-1823`). The pull raises the conflict. The prepare that follows merges the Catalog and sends the rest of the batch again as it was sent: the same operations (`replica.rs:426`).

Today the refused round fails instead, and the person sees "Sync interrupted" and waits 90 seconds. An automatic merge must not show either.

- This applies to every record kind: a host race reaches its review at once, without the error first.
- Other 409 answers (`retry`, `operation_reused`) keep today's handling.
- The re-pull counts against the round's request budget. A round re-pulls after a refusal at most a few times (the builder picks the bound) before failing as today.

### The automatic merge

It runs in the central dispatch's prepare (`active_dispatch.rs:300`), before the publish step (`:316`), when all of these hold:

1. the Catalog has a conflict, and it is settled (`conflicts::settled`);
2. the common version opens;
3. no item collides;
4. the merged Catalog holds within the limits, after "When it does not fit";
5. the library takes edits now (the publish step's gates).

It is one ordinary save, recomputed on the latest state inside the save, as the publish step saves (`record_runtime::mutate_records`). It:

- reads the merged Catalog into this device's rows, as the delta projection reads a Catalog (`projection_delta.rs:72-218`): collections with their account `Space` rows and `state.spaces`, the tunnel rows, the route rows and the Local group order. This device shows the other device's changes at once.
- replaces the Catalog's pending draft with the merged Catalog as the capture builds it from those rows. The draft expects the synced version's revision and keeps the synced version as its confirmed basis. The save also removes the Catalog's conflict entries. The capture after it then finds the Catalog's basis equal to the current Catalog and raises no new conflict. This is the path "Keep this device's version" takes today (`conflicts.rs:270-315`), with the merged Catalog in place of this device's.

Then the publish step and the capture run as today. After the merge the Catalog is settled (`catalog_settled`), so the publish step can move routes in during the same prepare. The push carries the merged Catalog, and the other device reads it on its next round. If that push meets a still newer Catalog (a third push in the window), the round pulls again and merges again on it ("A refused push").

There is no recovery snapshot: the merged Catalog keeps every change of both versions. There is also no notice. The review section may show the Catalog for the moment between the pull that raised the conflict and the prepare that merges it, in the same round.

### When it does not fit

The merged Catalog must pass `Catalog::validate` and `catalog_fits`. Otherwise:

1. **This device's new routes** (routes absent from both the common and the synced version) are kept in host-id order while the Catalog holds them. The first one that does not fit, and all after it, stay on this device as routes saved on this device alone (`local.transports`), as the publish step leaves a route that does not fit (`transports::local_routes`, `transports.rs:335`). They keep working on this device. The Google Cloud page lists them as "Saved on this computer only: the library has no room for this route" (`no_room`), and the publish step moves them in once there is room.
2. **If the Catalog still does not hold**, there is no automatic merge. The conflict stays for review, and its row says which limit was exceeded and what to do:
   - "Together, both devices’ changes hold 262 tunnels; a library holds at most 256. Remove some tunnels or routes on this device; Lunport combines both devices’ changes on the next sync."
   - for size: "Together, both devices’ changes are more than one library record holds (64 KB). Remove some tunnels or routes on this device; …"

   Every round tries again, so a removal on this device lets the next round merge. Nothing is dropped.

### Collisions: the review

The Catalog's row in Central conflicts (`CentralConflicts.tsx`) no longer reads "meta · meta" with JSON, and no longer says the record "contains key material or library structure". It shows:

> **Tunnels, routes and collections**
> Another device changed the same items at the same time. When you choose, Lunport keeps every other change from both devices. Until then, changes to tunnels, routes and collections wait on this device.

Then a table of the colliding items only: Item | This device | Synced version. For example:

- Tunnel “Database”, with the rule as the Tunnels panel summarizes it (e.g. "127.0.0.1:15432 → db.internal:5432 through prod-jump");
- Google Cloud route of “prod-jump”, as "project / instance · zone", plus whatever else differs (account, OS Login, PAM entitlements);
- Name of collection “Work”;
- Group order (or Group order in “<collection>”), with group names in order;
- "Removed" where a side removed the item.

Names come from the library, as the host comparison resolves them (`ConflictComparison`); ids are shown when a name is unknown.

While a collision waits for the choice, nothing of the Catalog is merged yet; the conflict stays whole, as today:

- this device does not read the other device's Catalog changes, since the delta projection skips a conflicted Catalog (`projection_delta.rs:248`);
- it does not send its own Catalog changes (`outbox.rs:154`);
- the publish step waits.

Its other records keep syncing. (Open question 1 below asks Frank whether to merge the non-colliding items first.)

There are two buttons: **Keep this device’s versions…** and **Use the synced versions…**. Each applies to the colliding items only, and every other item follows the rule. The confirmation asks "Keep this device’s versions of these items?" or "Use the synced versions of these items?" and says: "Every other change from both devices stays. Previous versions are kept in an encrypted local recovery snapshot on this device."

Confirming goes through today's resolve path (`conflicts::resolve`, `conflicts.rs:369`): the review token, the capture check and the recovery snapshot come before the choice is saved. Then the same transition as the automatic merge runs, with the chosen side for the colliding items and "When it does not fit" applied. A choice whose result would not hold is not offered, and the row shows the sentence instead.

What the row shows in the other states:

- No whole-Catalog choice and no "Keep both" are offered.
- A Catalog conflict without collisions that has not merged yet (between the pull and the prepare, or while the library refuses edits) shows "Lunport combines both devices’ changes on the next sync." and no buttons.
- An unsettled one shows today's sentence ("Sync must verify the pending write receipt before this conflict can be resolved.").

### Edge cases

- **An item is the smallest unit.** Two edits of one tunnel or one host's route collide even when they touched different fields.
- **Both devices add a route for the same host.** Different settings collide; identical ones do not. This can happen when both devices come from 1.12 with routes of their own.
- **A collection the synced version removed, while this device still holds hosts in it** (hosts not removed, or with changes not yet synced). The collection stays in the merged Catalog, so nothing is deleted silently, and the person can remove it again. The delta projection likewise refuses to drop such a collection (`projection_delta.rs:86-94`).
- **A common version that does not open** (e.g. across a key epoch). There is no automatic merge, and every item that differs between this device's and the synced version is a collision for review.
- **Tunnel rules this device keeps outside the account** (`local.tunnel_rules`) are part of this device's version, as the capture includes them, and the merge writes them as account rows, as the delta projection does.

### Conflict entries

A record in conflict keeps at most its 16 latest conflict entries; the oldest is dropped when a newer one is added. Today a 17th entry fails `Replica::validate` (`replica.rs:265`). That validation runs in both the capture and the pull, so a Catalog collision left for review would stop this device's sync after 16 more versions of the Catalog, or 16 local edits of it. Nothing reads an entry's contents: the review and the merge use the pending draft, the current version and the basis.

The status counts records in conflict, not entries (`controller.rs:140`), so one Catalog row reads "1 sync conflict needs review".

### What does not change

- The relay, the wire format, and the Catalog's shape and limits.
- The review of hosts, groups, keys and saved passwords.
- The publish step's conditions: it still waits while the Catalog is in conflict.
- `central_conflicts` still captures before listing.
- Older releases.

### Tests

**Rust, the rule (pure):**

- for each item kind: add/add (same, different), add here only, remove/remove, remove/edit, edit/edit (same, different), untouched;
- a deterministic merged order;
- a group order collides as a whole list.

**Rust, two devices (the done criterion).** Two devices of one library on one fake service each add a tunnel and a route inside one pull-to-push window. Use the central round fixture (`active_cycle_tests.rs`): either a second device, or the other device's pushes written into the service's history as `remote_catalog` writes them, timed so that this device's push is refused. The fixture's push stub must answer a stale expected revision with 409 `revision_conflict` and refuse the whole batch, as the relay does; today it asserts instead (`active_cycle_tests.rs:66`).

The refused device merges and pushes in the same round, with no error status and no backoff. After one more round on each device:

- both hold both tunnels and both routes (`tunnel_rules::view`, `transports::get`, `transports::synced`);
- nothing is pending or in conflict;
- no review was raised.

**Rust, a refused push:**

- a host race reaches review in the refused round;
- other 409 answers still fail the round;
- the re-pull bound holds.

**Rust, collisions:**

- the review lists the colliding items only;
- each choice keeps every other change from both devices;
- the snapshot is taken, and the token fences a changed conflict.

**Rust, room:**

- this device's new routes beyond the room stay local and show `no_room`, and the rest merges;
- 257 tunnels together keep the conflict with its sentence, and a removal lets the next round merge;
- a merged Catalog over 64 KiB is never published.

**Rust, edges:**

- a collection removed while this device holds hosts in it;
- an unopenable common version;
- an unsettled conflict is left alone;
- a library that refuses edits is left alone;
- an uncaptured edit survives the merge;
- the 16-entry cap;
- the status count.

**Frontend:**

- the Catalog row: title, sentence, item labels and values, resolved names, "Removed";
- both buttons and their dialogs;
- the "next sync" sentence and the room sentence, both without buttons;
- host conflicts unchanged.

### Documentation

`docs/development.md` (the routes paragraph, line 60) describes the merge. The Connect via design's "Conflicts" paragraph points here.

## Decided by Frank (2026-10-27)

1. The Connect via design's "one whole version is kept; no new conflict UI" for the Catalog is overturned: different items merge on their own, and only collisions are reviewed, in the new Catalog row.
2. A collision asks the person; it is not decided automatically.
3. There is no whole-Catalog choice: both buttons apply to the colliding items only.

## Open question for Frank

1. **While a collision waits for the choice, should the items that do not collide merge first?** This document assumes they wait (see "Collisions: the review").
   - Recommendation: they wait. Collisions are rare, and the status line asks for the review at once.
   - Merging first needs a provisional value for each colliding item until the person chooses. That is either the synced one, which puts this device's own edit out of sight on its screen until then, or this device's, which puts the other device's edit out of sight in the library. It also needs new stored state that holds the other version of each colliding item for the review, and a new review token and resolve path.
   - Cost if wrong: if the items wait and Frank wanted them merged first, then until the review this device does not get the other device's other tunnels, routes and collections, and does not send its own. Merging first can be added later on top of this design without redoing it. If they merge first and Frank wanted them to wait, it is a larger build and a screen where an edit seems undone.

## Left to the builder

- Names of functions, types and modules. A module for the rule beside `conflicts.rs` is expected.
- The data the Catalog row receives from `central_conflicts`, and whether the frontend or the backend formats the values.
- Whether the merge reuses `projection_delta::catalog` or a variant. Either way, versions of rows the merge writes stay monotonic and every row validates.
- How the two-device test produces the 409.
- Wording beyond the sentences quoted here.

## Calls I made (for Frank to check)

Accepted by Frank on 2026-10-27, with the proposal:

1. Automatic merges show no notice.
2. An item is the smallest unit; fields of one item are not merged.
3. Routes for the same host added on both devices with different settings collide.
4. A collection the other device removed stays while this device still holds hosts in it.
5. A common version that does not open sends every difference to review.
6. One choice applies to all colliding items.
7. Older releases keep today's behaviour.

Made while writing this document:

8. This device's version is what its rows hold now, so a change not yet captured is merged rather than overwritten.
9. A conflicted record keeps its 16 latest entries, and the status counts records, not entries.
10. A choice whose result would not fit is not offered.
11. A collision-free Catalog conflict waiting for the next round shows "Lunport combines both devices’ changes on the next sync." without buttons.
12. This device's new routes are kept in host-id order while they fit, as the publish step walks them.
13. A push refused for a stale revision makes the round pull again at once, for every record kind. A host race then reaches its review without first showing "Sync interrupted" and waiting 90 seconds.
