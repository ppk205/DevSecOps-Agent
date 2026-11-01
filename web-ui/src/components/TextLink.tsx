import { Link } from "react-router-dom";

interface TextLinkProps {
  to: string;
  children: React.ReactNode;
  className?: string;
}

export function TextLink({ to, children, className = "" }: TextLinkProps) {
  return (
    <Link
      to={to}
      className={`text-mbluedark underline-offset-4 transition-colors duration-150 ease-out hover:text-ink hover:underline ${className}`}
    >
      {children}
    </Link>
  );
}
