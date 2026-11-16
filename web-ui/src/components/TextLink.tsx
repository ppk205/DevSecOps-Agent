import { Link } from "react-router-dom";

interface TextLinkProps {
  to: string;
  children: React.ReactNode;
  className?: string;
}

/** Liên kết văn bản thuần: màu thân bài viết + luôn gạch chân (mBlue không đạt chuẩn AA khi dùng làm chữ). */
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
