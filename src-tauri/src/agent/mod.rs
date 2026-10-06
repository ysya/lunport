//! SSHelter 的 SSH agent(key roadmap 第 2 階段 spec §5)。
pub mod approval;
pub mod peer;
pub mod prompt;
pub mod protocol;
pub mod session;

/// agent 的執行期狀態(`AppState::agent`)。
#[derive(Default)]
pub struct AgentRuntime {
    pub prompts: prompt::PromptHub,
}
