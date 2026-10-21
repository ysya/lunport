import { describe, it, expect } from "vitest";
import { syncSummary, syncProblem, newerCentralStatus } from "./central-status";
import type { CentralStatus } from "./central-sync";
const base={available:true, configured:true, phase:"active", has_session:true, can_sync:true, pending:0, conflicts:0, automatic_sync:true, error:null} as CentralStatus;
describe("central sync status",()=>{
  it("does not require a legacy account to show automatic sync",()=>{
    expect(syncSummary(base)).toMatchObject({text:"Automatic encrypted sync",ready:true});
    expect(syncSummary({...base,configured:false})).toMatchObject({text:"Local library · Sync is optional",ready:false});
  });
  it("prioritizes revoked access, history review and locked devices over an old ready phase",()=>{
    for(const patch of [{phase:"revoked"},{needs_recovery:true},{replacement_pending:true},{needs_reconciliation:true},{phase:"awaiting_approval"}])
      expect(syncSummary({...base,...patch} as CentralStatus).ready).toBe(false);
    expect(syncSummary({...base,needs_reconciliation:true}).action).toBe("Review history");
  });
  it("never claims pending changes or failed attempts are synchronized",()=>{
    expect(syncSummary({...base,pending:2}).text).toContain("waiting to sync");
    expect(syncSummary({...base,error:"offline"})).toMatchObject({ready:false,text:"Sync interrupted · Changes saved locally"});
    expect(syncSummary({...base,cooldown_seconds:30}).ready).toBe(false);
    expect(syncSummary({...base,conflicts:2}).action).toBe("Review conflicts");
  });
  it("maps server failures to useful recovery instructions",()=>{
    expect(syncProblem("Invalid central sync protocol data.")).toContain("app and server are up to date");
    expect(syncProblem("The account changed.")).toContain("different account");
    expect(syncProblem("requested a cooldown")).toContain("waiting period");
  });
});

it("keeps a newer event when an earlier status request finishes later",()=>{
  const latest={...base,phase:"revoked",observation:"12"} as CentralStatus;
  expect(newerCentralStatus(latest,{...base,observation:"11"})).toBe(latest);
});

it("shows an in-progress password unlock instead of asking for the password again",()=>{
  expect(syncSummary({...base,phase:"awaiting_approval",connecting:true}).text).toContain("Unlocking and connecting");
});
