import { afterEach, describe, expect, it } from "vitest";

import { useUiStore } from "./ui";

afterEach(() => {
  useUiStore.setState({ selectedAlias: null, selectedFile: null });
});

describe("the host selection", () => {
  it("remembers the file of the row that was clicked, so the copies of one alias can be told apart", () => {
    useUiStore.getState().selectHost("web", "/home/f/.ssh/sshelter/work-8b01e4aa.config");
    expect(useUiStore.getState()).toEqual(
      expect.objectContaining({ selectedAlias: "web", selectedFile: "/home/f/.ssh/sshelter/work-8b01e4aa.config" }),
    );
  });

  it("forgets the file when an alias is selected from somewhere that has none: no copy is picked for the user", () => {
    useUiStore.getState().selectHost("web", "/home/f/.ssh/config");
    useUiStore.getState().setSelectedAlias("db");
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: "db", selectedFile: null }));
    useUiStore.getState().selectHost("web", "/home/f/.ssh/config");
    useUiStore.getState().setSelectedAlias(null);
    expect(useUiStore.getState()).toEqual(expect.objectContaining({ selectedAlias: null, selectedFile: null }));
  });
});
