import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";
import "./Button.css";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md";
  children: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  function Button(
    { variant = "secondary", size = "md", className, children, ...props },
    ref,
  ) {
    const classes = [
      "btn",
      `btn--${variant}`,
      `btn--${size}`,
      className,
    ]
      .filter(Boolean)
      .join(" ");

    return (
      <button ref={ref} className={classes} {...props}>
        {children}
      </button>
    );
  },
);
