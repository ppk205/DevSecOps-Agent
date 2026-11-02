import { useStrings } from "../i18n/lang";

export interface Column<T> {
  key: string;
  header: string;
  render: (row: T) => React.ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T, index: number) => string;
  emptyTitle?: string;
  emptyBody?: string;
}

/** Squared, hairline-ruled table with an EmptyState fallback. */
export function DataTable<T>({ columns, rows, rowKey, emptyTitle, emptyBody }: DataTableProps<T>) {
  const en = useStrings();
  if (rows.length === 0) {
    return (
      <div className="card p-10 text-center">
        <div className="label-m text-sm text-ink">{emptyTitle ?? en.common.emptyTitle}</div>
        <p className="mt-2 text-sm text-body">{emptyBody ?? en.common.emptyBody}</p>
      </div>
    );
  }
  return (
    <div className="card overflow-x-auto">
      <table className="w-full border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-hairline bg-soft">
            {columns.map((col) => (
              <th key={col.key} scope="col" className="label-m px-4 py-3 text-[11px] text-muted">
                {col.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr
              key={rowKey(row, i)}
              className="border-b border-hairline last:border-0 transition-colors duration-150 ease-out hover:bg-elevated"
            >
              {columns.map((col) => (
                <td key={col.key} className="px-4 py-3 text-body">
                  {col.render(row)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
