// DataTable — table primitive with header, body, empty, and loading
// states. Built on top of the new Table compound so every table in the
// app shares header styling, row hover, and cell padding.

import Spinner from './Spinner.jsx'
import EmptyState from './EmptyState.jsx'
import { Card } from './Card.jsx'
import { Table, THead, TBody, Tr, Th, Td } from './Table.jsx'

export default function DataTable({
  columns,
  rows,
  loading = false,
  emptyTitle = 'No results',
  emptyDescription = null,
  emptyAction = null,
  rowKey = (r, i) => r.id ?? i,
  onRowClick = null,
  className = '',
}) {
  if (loading) {
    return (
      <Card variant="flat" className={className}>
        <div className="p-12"><Spinner label="Loading records…" /></div>
      </Card>
    )
  }
  if (!rows || rows.length === 0) {
    return (
      <EmptyState
        title={emptyTitle}
        description={emptyDescription}
        action={emptyAction}
        className={className}
      />
    )
  }

  return (
    <Card variant="flat" className={`overflow-hidden ${className}`}>
      <Table>
        <THead>
          <tr>
            {columns.map((c) => (
              <Th key={c.key} align={c.align}>{c.header}</Th>
            ))}
          </tr>
        </THead>
        <TBody>
          {rows.map((r, i) => (
            <Tr
              key={rowKey(r, i)}
              onClick={onRowClick ? () => onRowClick(r) : undefined}
              className={onRowClick ? 'cursor-pointer' : ''}
            >
              {columns.map((c) => (
                <Td key={c.key} align={c.align} className={c.cellClassName || ''}>
                  {c.render ? c.render(r, i) : r[c.key]}
                </Td>
              ))}
            </Tr>
          ))}
        </TBody>
      </Table>
    </Card>
  )
}
