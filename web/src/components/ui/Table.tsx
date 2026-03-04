import type { ReactNode, TableHTMLAttributes } from "react";
import "./Table.css";

export interface TableProps extends TableHTMLAttributes<HTMLTableElement> {
  children: ReactNode;
}

export function Table({ className, children, ...props }: TableProps) {
  const classes = ["table-container", className].filter(Boolean).join(" ");

  return (
    <div className={classes}>
      <table className="table" {...props}>
        {children}
      </table>
    </div>
  );
}
