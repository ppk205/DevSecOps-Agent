import { Link } from "react-router-dom";

interface TextLinkProps {
  to: string;
  children: React.ReactNode;
  className?: string;
}

/** Plain-text link: body color + always underlined (mBlue fails AA as text). */
export function TextLink({ to, children, className = "" }: TextLinkProps) {
  return (
    <Link
      to={to}
      className={`text-body underline underline-offset-4 transition-colors duration-150 ease-out hover:text-ink ${className}`}
    >
      {children}
    </Link>
  );
}
