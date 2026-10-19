//! Compact immutable capture frames; omitted responses must come from the exact parent lineage.
use super::*;
impl Fetching {
    pub(in crate::sync::central) fn response_chains(&self) -> Vec<String> {
        self.responses.keys().cloned().collect()
    }
    pub(in crate::sync::central) fn inherit(
        &mut self,
        chains: &[String],
        previous: Option<Fetching>,
    ) -> Result<(), AppError> {
        if chains.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid());
        }
        let expected = previous
            .as_ref()
            .map_or_else(Vec::new, Self::response_chains);
        if chains != expected {
            return Err(invalid());
        }
        if let Some(previous) = previous {
            for (chain, response) in previous.responses {
                if let Some(saved) = self.responses.get(&chain) {
                    if saved.sequence != response.sequence || saved.records != response.records {
                        return Err(invalid());
                    }
                } else {
                    self.responses.insert(chain, response);
                }
            }
        }
        Ok(())
    }
    pub(in crate::sync::central) fn encode_delta(
        &self,
        inherited: &[String],
    ) -> Result<Zeroizing<Vec<u8>>, AppError> {
        #[derive(Serialize)]
        struct Delta<'a> {
            version: u32,
            local_context: &'a str,
            keybook: &'a str,
            operation: &'a str,
            progress: &'a Progress,
            responses: BTreeMap<&'a str, &'a Response>,
        }
        let delta = Delta {
            version: self.version,
            local_context: &self.local_context,
            keybook: &self.keybook,
            operation: &self.operation,
            progress: &self.progress,
            responses: self
                .responses
                .iter()
                .filter(|(chain, _)| !inherited.contains(chain))
                .map(|(chain, response)| (chain.as_str(), response))
                .collect(),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&delta).map_err(|_| invalid())?);
        if bytes.len() > MAX_FROZEN_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }
}
