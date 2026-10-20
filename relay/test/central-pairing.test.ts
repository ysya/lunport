import { expect, it } from "vitest";
import { validConfirmation, type PairingConfirmation } from "../src/v2/pairing";
import { base64 } from "../src/v2/protocol";
it("requires the complete authenticated Vault minima and an explicit personal Vault", () => {
  const vault = "a".repeat(64),
    other = "b".repeat(64),
    head = "c".repeat(64),
    request = "d".repeat(32);
  const value: PairingConfirmation = {
    request_id: request,
    approved_head: head,
    personal_vault: vault,
    minimums: [
      {
        vault,
        creation_head: head,
        creation_authorization_epoch: "2",
        key_epoch: "1",
        sequence: "0",
        history_hash: "0".repeat(64),
      },
    ],
    mac: base64(new Uint8Array(32).fill(9)),
  };
  expect(
    validConfirmation(value, request, head, { [vault]: { epoch: 1 } }, 3),
  ).toBe(true);
  for (const bad of [
    { ...value, personal_vault: other },
    { ...value, minimums: [] },
    { ...value, minimums: [...value.minimums, ...value.minimums] },
    { ...value, minimums: [{ ...value.minimums[0], sequence: "01" }] },
    { ...value, minimums: [{ ...value.minimums[0], history_hash: head }] },
    { ...value, minimums: [{ ...value.minimums[0], key_epoch: "2" }] },
    {
      ...value,
      minimums: [{ ...value.minimums[0], creation_authorization_epoch: "4" }],
    },
  ])
    expect(
      validConfirmation(bad, request, head, { [vault]: { epoch: 1 } }, 3),
    ).toBe(false);
  expect(
    validConfirmation(
      value,
      request,
      head,
      { [vault]: { epoch: 1 }, [other]: { epoch: 1 } },
      3,
    ),
  ).toBe(false);
});
