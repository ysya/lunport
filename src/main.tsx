import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { getCurrentWindow } from "@tauri-apps/api/window";
import App from "./App";
import AgentApprovalWindow from "./components/AgentApprovalWindow";
import "./index.css";

const queryClient = new QueryClient();

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("Root element #root not found in index.html");

// The agent's approval prompt (key vault spec §7.4) is a second window that loads the same page. Outside Tauri (a
// plain-browser `vite dev`) there is no window to ask, so the page is the app.
const isApprovalWindow = (() => {
  try {
    return getCurrentWindow().label === "approval";
  } catch {
    return false;
  }
})();

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <QueryClientProvider client={queryClient}>{isApprovalWindow ? <AgentApprovalWindow /> : <App />}</QueryClientProvider>
  </React.StrictMode>,
);
