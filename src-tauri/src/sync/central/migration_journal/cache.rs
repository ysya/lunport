//! Passive verified immutable-plan/read-prefix cache in the single SyncCore. Never authority.
use super::*;
pub(in crate::sync) struct CachedPlan {
    source: Receipt,
    receipt: Receipt,
    plan: Arc<Plan>,
}
pub(in crate::sync) struct CachedVerifier {
    plan: Arc<Plan>,
    prefix: Prefix,
    verifier: Verifier,
}
pub(super) fn plan(
    env: &SyncEnv,
    source: &Receipt,
    receipt: &Receipt,
    bytes: &[u8],
    owner: &Workspace,
    keys: &VaultKeys,
    signer: &DeviceKeys,
    context: &super::super::migration_history::Context,
) -> Result<Arc<Plan>, AppError> {
    // The caller just authenticated these exact ciphertext receipts and every named ancestor.
    let cached = env
        .runtime
        .core
        .lock()
        .unwrap()
        .migration_plan
        .as_ref()
        .filter(|cache| {
            &cache.source == source && &cache.receipt == receipt && cache.plan.before() == owner
        })
        .map(|cache| Arc::clone(&cache.plan));
    if let Some(plan) = cached {
        plan.require_keys(keys, signer)?;
        return Ok(plan);
    }
    let plan = Arc::new(Plan::decode_local(bytes, owner, keys, signer, context)?);
    env.runtime.core.lock().unwrap().migration_plan = Some(Box::new(CachedPlan {
        source: source.clone(),
        receipt: receipt.clone(),
        plan: Arc::clone(&plan),
    }));
    Ok(plan)
}
pub(super) fn verifier(
    env: &SyncEnv,
    loaded: &Loaded,
    keys: &VaultKeys,
) -> Result<Verifier, AppError> {
    let cached = env.runtime.core.lock().unwrap().migration_verifier.take();
    match cached {
        Some(cache)
            if Arc::ptr_eq(&cache.plan, &loaded.plan)
                && Some(&cache.prefix) == loaded.journal.verified.as_ref() =>
        {
            loaded.plan.require_read_keys(keys)?;
            if cache.verifier.snapshot(&loaded.plan)? != cache.prefix {
                return Err(invalid());
            }
            Ok(cache.verifier)
        }
        _ => loaded.verifier(keys),
    }
}
pub(super) fn remember_verifier(
    env: &SyncEnv,
    loaded: &Loaded,
    verifier: Verifier,
) -> Result<(), AppError> {
    let prefix = verifier.snapshot(&loaded.plan)?;
    env.runtime.core.lock().unwrap().migration_verifier = Some(Box::new(CachedVerifier {
        plan: Arc::clone(&loaded.plan),
        prefix,
        verifier,
    }));
    Ok(())
}
