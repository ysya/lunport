import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import AgentApprovalWindow from "./components/AgentApprovalWindow";
import AuthenticationWindow from "./components/AuthenticationWindow";
import HostKeyWindow from "./components/HostKeyWindow";
import "./index.css";
import { applyInitialMotionPreference } from "./lib/theme";

applyInitialMotionPreference();

const queryClient = new QueryClient();

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Root element #root not found in index.html");

// The agent's approval prompt (key vault spec §7.4) and the host key window (own-ssh spec §10) are windows of their own that load
// the same page. Outside Tauri (a plain-browser `vite dev`) there is no window to ask, so the page is the app.
const windowLabel = (() => {
  try {
    return getCurrentWindow().label;
  } catch {
    return "main";
  }
})();

function Root() {
  if (windowLabel === "approval") return <AgentApprovalWindow />;
  if (windowLabel === "authentication") return <AuthenticationWindow />;
  if (windowLabel === "hostkey") return <HostKeyWindow />;
  return <App />;
}

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>
      <Root />
    </QueryClientProvider>
  </React.StrictMode>,
);
