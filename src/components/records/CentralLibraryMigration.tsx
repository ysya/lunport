import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { centralStatus, type CentralStatus } from "@/lib/central-sync";
import {
  migrationKey,
  migrationScope,
  migrationStatus,
  prepareMigration,
  confirmMigration,
  continueMigration,
  type LibraryReview,
  type MigrationProgress,
} from "@/lib/central-migration";

export function libraryCanConfirm(
  progress: MigrationProgress | undefined,
  review: LibraryReview | null,
  acknowledged: boolean,
) {
  return (
    progress?.phase === "review" &&
    !progress.legacy_sources &&
    !progress.approved &&
    !!review &&
    !review.approved &&
    /^[0-9a-f]{64}$/.test(review.ticket) &&
    acknowledged
  );
}
export function LibraryReviewDetails({ review }: { review: LibraryReview }) {
  const summary = review.summary;
  return (
    <div className="space-y-3">
      <p>
        {summary.hosts} hosts · {summary.groups} Groups · {summary.collections}{" "}
        collections
      </p>
      <p>
        {summary.private_key_versions} managed private key versions and{" "}
        {summary.history_records} history records are included. Older retained
        versions stay in the encrypted history.
      </p>
      {summary.key_versions.length > 0 && (
        <ul
          className="max-h-64 space-y-2 overflow-y-auto"
          aria-label="Included key versions"
        >
          {summary.key_versions.map((key, index) => (
            <li key={index} className="rounded border p-2">
              <p>
                {key.name}
                {key.retained ? " (retained version)" : ""}
              </p>
              <p className="break-all font-mono text-xs">{key.fingerprint}</p>
              <p>
                {key.key_type} ·{" "}
                {key.storage === "managed"
                  ? key.has_passphrase
                    ? "Managed key, passphrase protected"
                    : "Managed key"
                  : key.storage === "hardware"
                    ? "Hardware key reference"
                    : "External agent reference"}
              </p>
            </li>
          ))}
        </ul>
      )}
      <p>
        Managed SSH private keys are encrypted before upload and become
        available on your approved devices. Hardware and external agent keys
        remain public references. Saved SSH passwords are encrypted with your
        library. Key passphrases stay on this device.
      </p>
    </div>
  );
}
const phaseText: Record<MigrationProgress["phase"], string> = {
  idle: "Review the complete library before enabling encrypted sync.",
  capturing: "Preparing and verifying the complete source snapshot.",
  waiting: "Waiting for the existing encrypted library to become available.",
  review: "Your complete library is ready for review.",
  staging: "Uploading the confirmed encrypted library.",
  reading: "Reading back and verifying the committed library.",
  publishing: "Finishing the protected local library transaction.",
  complete: "The encrypted library is connected.",
};
export function CentralLibraryMigration({
  status,
  disabled,
  onBusyChange,
  update,
}: {
  status: CentralStatus;
  disabled: boolean;
  onBusyChange: (busy: boolean) => void;
  update: (status: CentralStatus) => void;
}) {
  const client = useQueryClient();
  const key = migrationKey(status);
  const expected = migrationScope(status);
  const scope = JSON.stringify(key);
  const currentScope = useRef(scope);
  currentScope.current = scope;
  const eligible =
    status.available &&
    status.has_session &&
    (status.phase === "enrolled" ||
      (status.phase === "active" && status.needs_reconciliation)) &&
    !status.needs_recovery &&
    !status.replacement_pending;
  const inFlight = useRef(false);
  const [busy, setBusy] = useState(false);
  const query = useQuery({
    queryKey: key,
    queryFn: () => migrationStatus(expected),
    enabled: eligible && !busy,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: 5000,
  });
  const [review, setReview] = useState<{
    scope: string;
    value: LibraryReview;
  } | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(false);
  const generation = useRef(0);
  const queryFailure: unknown = query.error;
  const shown = review?.scope === scope ? review.value : null;
  const progress = query.data;
  const retiredSources = progress?.legacy_sources === true;
  useEffect(() => {
    if (progress?.phase !== "complete" || !eligible) return;
    let cancelled = false;
    const selected = scope;
    void centralStatus()
      .then((next) => {
        if (!cancelled && mounted.current && currentScope.current === selected)
          update(next);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [progress?.phase, eligible, scope, update]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current += 1;
    };
  }, []);
  useEffect(() => {
    generation.current += 1;
    setReview(null);
    setAcknowledged(false);
    setError(null);
  }, [scope, status.phase, status.has_session]);
  useEffect(() => {
    const hide = () => {
      if (document.hidden) {
        generation.current += 1;
        setReview(null);
        setAcknowledged(false);
      }
    };
    document.addEventListener("visibilitychange", hide);
    return () => document.removeEventListener("visibilitychange", hide);
  }, []);
  useEffect(() => {
    onBusyChange(busy);
    return () => onBusyChange(false);
  }, [busy, onBusyChange]);
  const run = async (action: (current: () => boolean) => Promise<void>) => {
    if (disabled || inFlight.current || !eligible) return;
    const requested = scope;
    const token = generation.current;
    const current = () =>
      mounted.current &&
      currentScope.current === requested &&
      generation.current === token;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      await client.cancelQueries({ queryKey: key, exact: true });
      if (current()) await action(current);
    } catch (failure) {
      if (current())
        setError(
          typeof failure === "string"
            ? failure
            : "Could not continue library migration. Your original sources and progress are retained.",
        );
    } finally {
      inFlight.current = false;
      if (mounted.current) setBusy(false);
    }
  };
  const prepare = () =>
    run(async (current) => {
      const result = await prepareMigration(expected);
      if (!current()) return;
      client.setQueryData(key, result.progress);
      setReview(result.review ? { scope, value: result.review } : null);
      setAcknowledged(false);
    });
  const confirm = () =>
    run(async (current) => {
      if (!libraryCanConfirm(progress, shown, acknowledged)) return;
      const result = await confirmMigration(expected, shown!.ticket);
      if (!current()) return;
      client.setQueryData(key, result);
      setReview(null);
      setAcknowledged(false);
    });
  const advance = () =>
    run(async (current) => {
      const result = await continueMigration(expected);
      if (!current()) return;
      client.setQueryData(key, result);
    });
  if (!eligible) return null;
  const blocked = disabled || busy;
  return (
    <section
      className="space-y-3 border-t pt-4"
      aria-label="Encrypted library setup"
    >
      <h3 className="font-medium">
        {status.needs_reconciliation
          ? "Reconcile restored library"
          : progress?.mode === "join"
          ? "Connect this device"
          : "Enable encrypted library sync"}
      </h3>
      <p>
        {progress
          ? phaseText[progress.phase]
          : "Checking saved migration progress."}
      </p>
      {status.needs_reconciliation && (
        <p>Review the restored history before merging it with your encrypted library. Original files stay preserved; sync resumes after the merge is verified.</p>
      )}
      {progress?.mode === "publish" && !progress.approved && (
        <p>
          Original local data and saved progress are retained until this library setup finishes.
        </p>
      )}
      {retiredSources && (
        <p role="alert">
          This saved setup requires the retired chain service and cannot continue. Your local files are retained. Start a new Records workspace, import hosts from the old local sync-state.json, then enable encrypted library sync.
        </p>
      )}
      {progress?.mode === "join" && progress.phase === "waiting" && (
        <p>
          Verify the existing encrypted library before connecting this device.
          Any local data will be reviewed as a separate merge before upload.
        </p>
      )}
      {progress && progress.total > 0 && (
        <p>
          {progress.mode === "join"
            ? `${progress.verified} of ${progress.total} records verified · ${progress.staged} local records merged`
            : `${progress.staged} of ${progress.total} records staged · ${progress.verified} verified by readback`}
        </p>
      )}
      {shown && !shown.approved && !retiredSources && (
        <>
          <LibraryReviewDetails review={shown} />
          <label className="flex items-start gap-2">
            <input
              type="checkbox"
              checked={acknowledged}
              disabled={blocked}
              onChange={(event) => setAcknowledged(event.target.checked)}
            />
            <span>
              I agree to sync this complete library, including saved SSH passwords and the managed SSH
              private keys shown above, to my approved devices.
            </span>
          </label>
          <Button
            disabled={
              blocked || !libraryCanConfirm(progress, shown, acknowledged)
            }
            onClick={() => void confirm()}
          >
            Confirm library sync
          </Button>
        </>
      )}
      {!shown && progress && !progress.approved && !retiredSources && (
        <Button disabled={blocked} onClick={() => void prepare()}>
          {progress.phase === "idle"
            ? "Prepare library review"
            : progress.phase === "review"
              ? "Review complete library"
              : "Continue preparing"}
        </Button>
      )}
      {progress?.approved && progress.phase !== "complete" && !retiredSources && (
        <Button disabled={blocked} onClick={() => void advance()}>
          Continue library sync
        </Button>
      )}
      {Boolean(error || queryFailure) && (
        <p role="alert">
          {error ??
            (typeof queryFailure === "string"
              ? queryFailure
              : "Could not read migration progress. Your original data is retained.")}
        </p>
      )}
    </section>
  );
}
