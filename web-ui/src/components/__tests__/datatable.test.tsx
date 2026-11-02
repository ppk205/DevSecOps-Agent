import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DataTable } from "../DataTable";

interface Row {
  id: string;
  name: string;
}

const COLUMNS = [
  { key: "id", header: "ID", render: (r: Row) => r.id },
  { key: "name", header: "Name", render: (r: Row) => r.name },
];

describe("DataTable", () => {
  it("renders rows and headers", () => {
    render(
      <DataTable
        columns={COLUMNS}
        rows={[{ id: "a", name: "Alpha" }]}
        rowKey={(r) => r.id}
      />,
    );
    expect(screen.getByText("ID")).toBeInTheDocument();
    expect(screen.getByText("Alpha")).toBeInTheDocument();
  });

  it("shows the empty state when there are no rows", () => {
    render(<DataTable columns={COLUMNS} rows={[]} rowKey={(r) => r.id} />);
    expect(screen.getByText("Nothing here yet")).toBeInTheDocument();
  });
});
