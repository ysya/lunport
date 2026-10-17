import { describe, it, expect } from "vitest";
import { groupComparator, moveGroup } from "./group-order";
import { buildRecordTree } from "./group-tree";
import { groupView, recordOverview } from "./fixtures";

describe("custom group navigation order", () => {
  it("orders roots and children consistently without changing their parents or defaults", () => {
    const a = groupView({ id: "a", payload: {schema:1,name:"Alpha",parent_id:null,defaults:{}} });
    const b = groupView({ id: "b", payload: {schema:1,name:"Beta",parent_id:null,defaults:{}} });
    const child = groupView({ id: "c", payload: {schema:1,name:"Child",parent_id:"a",defaults:{port:2222}} });
    const o = recordOverview({groups:[a,b,child], group_order:{ids:["b","c","a"],revision:null,blocked:false,sync_enabled:true}});
    const roots = buildRecordTree(o)[0].groups;
    expect(roots.map((r) => r.group.id)).toEqual(["b","a"]);
    expect(roots[1].children[0].group).toEqual(child);
    expect([...o.groups].sort(groupComparator([])).map((g) => g.id)).toEqual(["a","b","c"]);
  });
  it("keeps hidden groups in the rank list and adds new siblings before moving", () => {
    expect(moveGroup(["a","hidden","b"],["a","b","new"],"new","a","before"))
      .toEqual(["new","hidden","a","b"]);
    expect(moveGroup(["a","hidden","b"],["a","b"],"b","a","before"))
      .toEqual(["b","hidden","a"]);
  });
  it("refuses cross-level and self drops, preserving collapsed subtree membership", () => {
    expect(moveGroup(["a","b","child"],["a","b"],"child","b","after")).toBeNull();
    expect(moveGroup(["a","b"],["a","b"],"a","a","before")).toBeNull();
    expect(moveGroup(["a","b"],["a","b"],"a","b","before")).toBeNull();
  });
});
