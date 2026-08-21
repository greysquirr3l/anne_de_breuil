//! Terminal rendering for [`crate::application::fanout::ProgressReporter`]:
//! a `MultiProgress` spinner per host, drawn to stderr only, hidden
//! entirely when stderr isn't a TTY.
//!
//! This is the adapter, not a second port — the trait lives in
//! `application::fanout` because that's the use case that consumes it.
//! Nothing above this module ever imports `indicatif` or `console`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};

use crate::application::fanout::{HostOutcome, NullProgressReporter, ProgressReporter};
use crate::domain::HostId;

const BRAILLE_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const ASCII_FRAMES: [&str; 4] = ["-", "\\", "|", "/"];

/// `ANNE_ASCII` forces the legacy-console fallback regardless of what
/// [`terminal_supports_braille`] detects — an operator override for a
/// terminal this crate doesn't know how to recognise.
const ASCII_OVERRIDE_ENV: &str = "ANNE_ASCII";

/// A `LazyLock` initializer must be infallible, and `with_template` isn't
/// (a malformed template is a `Result::Err`) — `unwrap_or_else` falls back
/// to `default_spinner` rather than tripping `clippy::unwrap_used` on a
/// template string that is, in fact, always valid at compile time.
static STYLE: LazyLock<ProgressStyle> = LazyLock::new(|| {
    ProgressStyle::with_template("{spinner:.dim} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
        .tick_strings(&frame_set())
});

fn frame_set() -> Vec<&'static str> {
    if use_ascii_frames() {
        ASCII_FRAMES.to_vec()
    } else {
        BRAILLE_FRAMES.to_vec()
    }
}

fn use_ascii_frames() -> bool {
    std::env::var(ASCII_OVERRIDE_ENV).is_ok() || !terminal_supports_braille()
}

/// Legacy conhost raster fonts have no U+2800 block coverage, so braille
/// frames are only offered to a terminal known to render them: a
/// known-good `TERM_PROGRAM`, or Windows Terminal via `WT_SESSION`
/// (`WT_SESSION` is set by Windows Terminal itself, unlike conhost or
/// `ConEmu`, which don't set it).
fn terminal_supports_braille() -> bool {
    matches!(
        std::env::var("TERM_PROGRAM").as_deref(),
        Ok("vscode" | "WezTerm" | "iTerm.app")
    ) || std::env::var("WT_SESSION").is_ok()
}

/// A per-host spinner reporter backed by `indicatif`. Construct via
/// [`new`], not directly — that's what picks this adapter over
/// [`NullProgressReporter`] based on whether stderr is actually a TTY.
pub struct IndicatifProgress {
    multi: MultiProgress,
    bars: Mutex<HashMap<HostId, ProgressBar>>,
    finished: AtomicBool,
    // Counts how many times `finish()`'s guarded body actually ran —
    // exists so the idempotency guarantee can be asserted directly rather
    // than inferred from indirect state, see `finish_is_idempotent` below.
    finish_calls: AtomicUsize,
}

impl IndicatifProgress {
    fn with_draw_target(target: ProgressDrawTarget) -> Self {
        Self {
            multi: MultiProgress::with_draw_target(target),
            bars: Mutex::new(HashMap::new()),
            finished: AtomicBool::new(false),
            finish_calls: AtomicUsize::new(0),
        }
    }

    fn lock_bars(&self) -> std::sync::MutexGuard<'_, HashMap<HostId, ProgressBar>> {
        self.bars
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Which adapter [`new`] should build, decided once so the decision
/// itself is testable without needing a real non-TTY process to construct
/// one in a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterKind {
    /// stderr is a real terminal — render spinners.
    Terminal,
    /// stderr is redirected, piped, or otherwise not a controlling
    /// terminal (a scheduled task/RMM invocation, output captured by a
    /// test harness) — stay silent.
    Null,
}

const fn choose_adapter(is_term: bool) -> AdapterKind {
    if is_term {
        AdapterKind::Terminal
    } else {
        AdapterKind::Null
    }
}

/// Picks the terminal spinner adapter when stderr is a real TTY, and the no-op adapter otherwise.
///
/// A hidden draw target would still render nothing, but skipping
/// construction entirely means a non-interactive run never pays for a
/// `MultiProgress` it can't use.
#[must_use]
pub fn new() -> Arc<dyn ProgressReporter> {
    match choose_adapter(console::Term::stderr().is_term()) {
        AdapterKind::Terminal => Arc::new(IndicatifProgress::with_draw_target(
            ProgressDrawTarget::stderr(),
        )),
        AdapterKind::Null => Arc::new(NullProgressReporter),
    }
}

const fn outcome_glyph(outcome: &HostOutcome) -> &'static str {
    match outcome {
        HostOutcome::Succeeded(_) => "done",
        HostOutcome::Failed(_) => "failed",
        HostOutcome::TimedOut => "timed out",
    }
}

impl ProgressReporter for IndicatifProgress {
    fn host_started(&self, host_id: HostId) {
        let bar = self.multi.add(ProgressBar::new_spinner());
        bar.set_style(STYLE.clone());
        bar.enable_steady_tick(std::time::Duration::from_millis(120));
        bar.set_message(host_id.to_string());
        self.lock_bars().insert(host_id, bar);
    }

    fn host_finished(&self, host_id: HostId, outcome: &HostOutcome) {
        let bar = self.lock_bars().remove(&host_id);
        if let Some(bar) = bar {
            bar.finish_with_message(format!("{host_id} {}", outcome_glyph(outcome)));
        }
    }

    fn finish(&self) {
        if self
            .finished
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.finish_calls.fetch_add(1, Ordering::SeqCst);
            for (_, bar) in self.lock_bars().drain() {
                bar.abandon();
            }
            let _ = self.multi.clear();
        }
    }
}

impl Drop for IndicatifProgress {
    fn drop(&mut self) {
        // A run that never called `finish()` — panicked, or the caller
        // just forgot — must not leave a spinner rendered forever with no
        // process left ticking it. Abandon whatever's still live and mark
        // it interrupted rather than "done".
        if !self.finished.load(Ordering::SeqCst) {
            for (host_id, bar) in self.lock_bars().drain() {
                bar.abandon_with_message(format!("{host_id} interrupted"));
            }
            let _ = self.multi.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex as StdMutex, OnceLock};

    use super::{
        ASCII_OVERRIDE_ENV, AdapterKind, IndicatifProgress, Ordering, ProgressDrawTarget,
        ProgressReporter, choose_adapter, use_ascii_frames,
    };
    use crate::application::fanout::HostOutcome;
    use crate::domain::HostId;

    /// Same pattern as `adapters::config::mod`'s `env_lock` — tests that
    /// mutate `TERM_PROGRAM`/`WT_SESSION`/`ANNE_ASCII` must be serialized
    /// against each other, or a parallel test run flips the answer out
    /// from under a concurrently running one.
    fn env_lock() -> &'static StdMutex<()> {
        static LOCK: OnceLock<StdMutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| StdMutex::new(()))
    }

    /// SAFETY: every call site holds `env_lock` for the duration of the
    /// mutation and the read that depends on it, so no other test observes
    /// a partially-applied environment.
    unsafe fn set_or_clear(key: &str, value: Option<&str>) {
        match value {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    fn ascii_fallback_selection_table() {
        let _guard = env_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        for (term_program, wt_session, ascii_override, expect_ascii) in [
            // Known-good TERM_PROGRAM, no override -> braille.
            (Some("vscode"), None, None, false),
            // WT_SESSION set, no TERM_PROGRAM -> braille (Windows Terminal).
            (None, Some("1"), None, false),
            // Neither known-good -> ascii.
            (None, None, None, true),
            // ANNE_ASCII wins even over a known-good TERM_PROGRAM.
            (Some("vscode"), None, Some("1"), true),
        ] {
            unsafe {
                set_or_clear("TERM_PROGRAM", term_program);
                set_or_clear("WT_SESSION", wt_session);
                set_or_clear(ASCII_OVERRIDE_ENV, ascii_override);
            }

            let is_ascii = use_ascii_frames();

            unsafe {
                set_or_clear("TERM_PROGRAM", None);
                set_or_clear("WT_SESSION", None);
                set_or_clear(ASCII_OVERRIDE_ENV, None);
            }

            assert_eq!(
                is_ascii, expect_ascii,
                "TERM_PROGRAM={term_program:?} WT_SESSION={wt_session:?} \
                 ANNE_ASCII={ascii_override:?}"
            );
        }
    }

    #[test]
    fn finish_is_idempotent() {
        let progress = IndicatifProgress::with_draw_target(ProgressDrawTarget::hidden());
        let host_id = HostId::generate();
        progress.host_started(host_id);
        progress.host_finished(host_id, &HostOutcome::TimedOut);

        progress.finish();
        progress.finish();

        assert_eq!(progress.finish_calls.load(Ordering::SeqCst), 1);
        assert!(progress.finished.load(Ordering::SeqCst));
    }

    #[test]
    fn finish_drains_any_bar_still_open() {
        let progress = IndicatifProgress::with_draw_target(ProgressDrawTarget::hidden());
        progress.host_started(HostId::generate());
        assert_eq!(progress.lock_bars().len(), 1);

        progress.finish();

        assert!(progress.lock_bars().is_empty());
    }

    #[test]
    fn drop_without_finish_does_not_panic() {
        let progress = IndicatifProgress::with_draw_target(ProgressDrawTarget::hidden());
        progress.host_started(HostId::generate());
        drop(progress);
    }

    #[test]
    fn null_adapter_selected_when_stderr_is_not_a_tty() {
        assert_eq!(choose_adapter(false), AdapterKind::Null);
        assert_eq!(choose_adapter(true), AdapterKind::Terminal);
    }

    /// `new()` feeds `choose_adapter` from `console::Term::stderr().is_term()`
    /// directly — this confirms that under `cargo test`'s captured stdio,
    /// that real detection actually lands on the `Null` branch the test
    /// above exercises, rather than the branch selection being correct in
    /// isolation but never actually reached by `new()` in CI.
    #[test]
    fn stderr_is_not_a_tty_under_the_test_harness() {
        assert!(
            !console::Term::stderr().is_term(),
            "this test assumes a non-interactive test runner; if it fails, \
             cargo test is somehow attached to a real terminal on stderr"
        );
    }
}
