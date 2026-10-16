import type { ComponentProps } from "react";
import { DialogContent } from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

/** Bounded task surface: persistent heading/actions and one scrollable body. */
export function TaskDialogContent({ className, ...props }: ComponentProps<typeof DialogContent>) {
  return <DialogContent className={cn("app-task-dialog", className)} {...props} />;
}
export function TaskDialogBody({ className, ...props }: ComponentProps<"div">) {
  return <div className={cn("app-task-body min-h-0 overflow-y-auto", className)} {...props} />;
}
