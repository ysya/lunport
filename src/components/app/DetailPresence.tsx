import { createContext, useContext, useEffect, useLayoutEffect, useRef, useState, type ReactNode } from "react";

const DetailMotion = createContext({ open: true, finish: () => {} });
export const useDetailMotion = () => useContext(DetailMotion);

/** Retain only public detail content during exit. Selection and focus change immediately. */
export function DetailPresence({ children }: { children: ReactNode }) {
  const open = children !== null && children !== false && children !== undefined;
  const [retained, setRetained] = useState(children);
  const isOpen = useRef(open);
  isOpen.current = open;
  const finish = () => { if (!isOpen.current) setRetained(null); };
  useLayoutEffect(() => { if (open) setRetained(children); }, [children, open]);
  useEffect(() => {
    if (open) return;
    // Animationend normally removes the pane, including under reduced motion.
    // A fallback also releases it when CSS is unavailable or the animation is cancelled.
    const timeout = window.setTimeout(finish, 280);
    return () => window.clearTimeout(timeout);
  }, [open]);
  return <DetailMotion.Provider value={{ open, finish }}>{open ? children : retained}</DetailMotion.Provider>;
}
