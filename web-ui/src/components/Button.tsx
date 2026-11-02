import type { ButtonHTMLAttributes } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";
type Size = "sm" | "md";

const VARIANTS: Record<Variant, string> = {
  primary: "bg-mbluedark text-ink hover:bg-mblue",
  secondary: "border border-hairline text-ink hover:border-muted",
  danger: "bg-mred text-ink hover:bg-[#f04434]",
  ghost: "text-body hover:text-ink",
};

const SIZES: Record<Size, string> = {
  sm: "px-3 py-1.5 text-xs",
  md: "px-5 py-2.5 text-sm",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
}

/** Squared M-dark button. Only circular icon buttons get radius (see IconButton). */
export function Button({ variant = "primary", size = "md", className = "", ...rest }: ButtonProps) {
  return (
    <button
      className={`label-m rounded-none transition-colors duration-200 ease-out disabled:cursor-not-allowed disabled:opacity-40 ${VARIANTS[variant]} ${SIZES[size]} ${className}`}
      {...rest}
    />
  );
}

/** Circular icon-only button — the single allowed 48px-radius surface. */
export function IconButton({
  label,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      aria-label={label}
      title={label}
      className={`icon-btn flex h-12 w-12 items-center justify-center border border-hairline text-ink transition-colors duration-200 ease-out hover:border-muted ${className}`}
      {...rest}
    />
  );
}
