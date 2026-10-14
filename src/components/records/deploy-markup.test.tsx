import { expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Dialog } from "@/components/ui/dialog";
import { RecordsDeployContent } from "./DeployKeyDialog";
import { recordOverview } from "./fixtures";
const preview = { id:"preview", host_id:"host", key_id:"key", alias:"web", hostname:"web.example", port:22, user:"ops", route:Array.from({length:16},(_,i)=>`hop-${i}@jump.example:22`), key_name:"Laptop", fingerprint:"SHA256:public-identity", public_key:"public fixture" };
const noop = () => {};
function render(phase: "idle" | "running" = "idle", authorized = false) {
 return renderToStaticMarkup(<Dialog open><RecordsDeployContent overview={recordOverview()} hostId="host" preview={preview} authorized={authorized} phase={phase} result={null} error={null} onHostChange={noop} onRefresh={noop} onAuthorize={noop} onDeploy={noop} onCancel={noop} onClose={noop} /></Dialog>);
}
it("keeps complete route in its own scrolling region and identity before the route, outside fixed actions", () => {
 const html=render();
 expect(html).toContain("Deployment details");expect(html).toContain("overflow-y-auto");
 expect(html.indexOf("SHA256:public-identity")).toBeLessThan(html.indexOf("hop-0@"));
 expect(html).toContain("hop-15@");
 const detailsEnd=html.indexOf('</section>');
 expect(html.indexOf("Confirm deployment")).toBeGreaterThan(detailsEnd);
 expect(html).toMatch(/<button[^>]*disabled=""[^>]*>Confirm deployment<\/button>/);
 expect(render("idle",true)).not.toMatch(/<button[^>]*disabled=""[^>]*>Confirm deployment<\/button>/);
});
it("keeps cancel and in-progress status in the fixed action area", () => {
 const html=render("running");expect(html).toContain("Deployment actions");expect(html).toContain("Cancel deployment");expect(html).toContain('role="status"');expect(html).not.toContain(">Confirm deployment<");
});
