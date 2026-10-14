import { cloneElement, isValidElement, useId, type ReactNode } from "react";
import { Label } from "@/components/ui/label";
export const selectClass =
  "h-9 w-full min-w-0 rounded-md border border-input bg-transparent px-3 text-sm outline-none focus:border-ring disabled:opacity-50";
export function RecordField({
  label,
  children,
}: {
  label: string;
  children: ReactNode;
}) {
  const id = useId();
  const nodes = Array.isArray(children) ? children : [children];
  let assigned = false;
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      {nodes.map((child, index) => {
        if (
          !assigned &&
          isValidElement<{ id?: string }>(child) &&
          "value" in child.props
        ) {
          assigned = true;
          return cloneElement(child, { id, key: index });
        }
        return child;
      })}
    </div>
  );
}
