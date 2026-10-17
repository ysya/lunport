# Protocol and username card preview

This revision follows the user's Termius screenshot: name on the first line, then `SSH · username` with an optional short warning. If the username is unset, show `SSH`; the hint explains that the OS username will be used. Address and port remain in the hint and existing Host Details. There is no new protocol field or Telnet claim; the current connection engine uses SSH.

- [Overview](overview-dark.jpg), using 20 synthetic hosts with different usernames.
- [Selected password-authenticated host](details-password.jpg), showing the address, username, port and Authentication → Password in the existing details pane.
- [Responsive measurements](responsive-metrics.json): 1240/860/540/360px with the sidebar collapsed, equal 63.75px card heights at a 15px base font, no horizontal page overflow, no clipped or out-of-card warnings.
- TypeScript, all 86 frontend files / 1,078 tests and the production Vite build pass. The fixture never launches SSH or reads Production App data.

## Existing password support: read-only audit

The current Records host editor already offers Password, SSH key and Keyboard interactive authentication (`src/components/records/HostEditor.tsx`). Password mode explicitly says that the terminal requests the password. `records_connect` launches the existing terminal helper; RecordDirectory maps `AuthKind::Password` to `AuthMethod::Password`. The shared authentication engine accepts a terminal answer and can read an existing local credential. Its current terminal answer remains in connection memory rather than being automatically persisted.

`session::record_directory::tests::records_connect_through_the_real_engine_and_persist_first_contact` is an existing real-engine test with a local password-authenticated toy server and an in-memory keychain. This turn inspected that test and the runtime path; it did not rerun native authentication or launch a real connection.

The Records editor currently has no prefilled-password or Remember password field. An app-side entry/save flow is a separate proposed UX improvement, not a feature implemented by this card preview. No credential storage, native code, server authentication policy or sync format changes in this revision. This remains a draft preview, with no merge or release.
