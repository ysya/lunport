# Host card interactions

The card body selects on one click and connects on double-click or Enter. The
right-hand pencil opens the saved host editor as a full-height drawer. It appears
on hover, keyboard focus or selection, and stays visible on touch devices.

The drawer overlays the catalog. Clicking the space outside closes a clean editor;
unsaved drafts retain the existing Keep editing / Discard changes confirmation.
Escape and focus restoration use the existing Dialog behavior. The drawer retains
its placement during the closing animation and respects reduced motion. New host
and Group creation keep their existing forms.

Connection details, the port check and server identity manager remain accessible
through the host's context menu. Clicking catalog space closes those details;
selecting another card closes them without opening a second pane.

Actual component screenshots with synthetic data:

- [Card selection and right-side edit button](cards.jpg)
- [Saved host editor drawer](editor-drawer.jpg)

The external Funlingo browser toolbar in these images is not part of Lunport.
The live development fixture is `/dev-preview.html?scenario=host-interactions`.
It logs fake connection requests and never opens a terminal or SSH connection.

Validation: TypeScript, all 89 frontend files / 1,099 tests, and production build.
Browser checks verified single-click selection without an editor, one connection
request per double-click, Enter connection, double-clicking the pencil without a
connection, clean outside-click close, dirty draft retention/discard, Escape/focus
restoration, context-menu details and outside close, and no connection in batch
selection mode or for a host missing its key.

At a 979px viewport the catalog grid remained 722.875px wide with the same top
position (154.5px) before/after opening the editor. At the supported minimum
800×560 size the drawer occupied x=320…800, the footer stayed inside the viewport,
the form scrolled, and the document had no horizontal overflow. The temporary
viewport override was reset after verification.
