import { useEffect, useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useDebounced } from "./use-debounced";

// There is no DOM to run a component in, and the hook needs only state and effects: `component` below gives it both, the way React gives
// them to one component.
vi.mock("react", async (original) => ({ ...(await original<typeof import("react")>()), useState: vi.fn(), useEffect: vi.fn() }));

/**
 * Runs `hook` as the only hook of a component. Its state lives from one render to the next; after a render, an effect whose
 * dependencies changed runs, after the cleanup of the one before it, as React does it; and a state change that comes from outside a
 * render (a timer going off) draws the component again, with the input it last had.
 */
function component<Input, Output>(hook: (input: Input) => Output) {
  let cell: { value: unknown } | undefined;
  let dependencies: readonly unknown[] | undefined;
  let cleanup: void | (() => void);
  let queued: (() => void) | undefined;
  let input!: Input;
  let output!: Output;
  let changed = false;
  let mounted = true;
  vi.mocked(useState).mockImplementation(((initial: unknown) => {
    const own = (cell ??= { value: typeof initial === "function" ? (initial as () => unknown)() : initial });
    return [
      own.value,
      (next: unknown) => {
        const value = typeof next === "function" ? (next as (current: unknown) => unknown)(own.value) : next;
        if (!Object.is(value, own.value)) {
          own.value = value;
          changed = true;
        }
      },
    ];
  }) as never);
  vi.mocked(useEffect).mockImplementation(((effect: () => void | (() => void), next: readonly unknown[]) => {
    if (dependencies && next.every((dependency, index) => Object.is(dependency, dependencies![index]))) return;
    dependencies = next;
    queued = () => {
      if (typeof cleanup === "function") cleanup();
      cleanup = effect();
    };
  }) as never);
  const render = (next: Input): Output => {
    input = next;
    output = hook(next);
    const effect = queued;
    queued = undefined;
    effect?.();
    return output;
  };
  return {
    render,
    /** What the component shows once whatever the timers changed has been drawn. */
    shown: (): Output => {
      while (changed && mounted) {
        changed = false;
        render(input);
      }
      return output;
    },
    unmount: () => {
      mounted = false;
      if (typeof cleanup === "function") cleanup();
    },
  };
}

describe("useDebounced", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  const typed = (delay = 400) => component((value: string) => useDebounced(value, delay));
  const wait = (ms: number) => vi.advanceTimersByTime(ms);

  it("shows_the_first_value_at_once", () => {
    const input = typed();
    expect(input.render("acme-prod-123456")).toBe("acme-prod-123456");
    // A value that is already shown has nothing to wait for.
    expect(vi.getTimerCount()).toBe(0);
    wait(1000);
    expect(input.shown()).toBe("acme-prod-123456");
  });

  it("shows_a_change_only_once_the_delay_has_passed", () => {
    const input = typed();
    input.render("acme");
    expect(input.render("acme-")).toBe("acme");
    wait(399);
    expect(input.shown()).toBe("acme");
    wait(1);
    expect(input.shown()).toBe("acme-");
  });

  it("typing_on_starts_the_wait_again_and_only_the_last_value_shows", () => {
    const input = typed();
    input.render("a");
    input.render("ab");
    wait(300);
    // Another character before the first one's wait is over: that wait is gone, and "ab" never shows.
    input.render("abc");
    wait(399);
    expect(input.shown()).toBe("a");
    wait(1);
    expect(input.shown()).toBe("abc");
    wait(5000);
    expect(input.shown()).toBe("abc");
  });

  it("a_value_that_changes_back_before_the_delay_leaves_what_was_shown_alone", () => {
    const input = typed();
    input.render("a");
    input.render("b");
    wait(100);
    input.render("a");
    wait(5000);
    expect(input.shown()).toBe("a");
  });

  it("waits_as_long_as_it_is_told", () => {
    const input = typed(50);
    input.render("a");
    input.render("b");
    wait(49);
    expect(input.shown()).toBe("a");
    wait(1);
    expect(input.shown()).toBe("b");
  });

  it("follows_the_value_again_after_it_settled", () => {
    const input = typed();
    input.render("a");
    input.render("b");
    wait(400);
    expect(input.shown()).toBe("b");
    expect(input.render("c")).toBe("b");
    wait(400);
    expect(input.shown()).toBe("c");
  });

  it("leaves_no_timer_behind_when_the_component_goes_away", () => {
    const input = typed();
    input.render("a");
    input.render("b");
    expect(vi.getTimerCount()).toBe(1);
    input.unmount();
    expect(vi.getTimerCount()).toBe(0);
  });
});
