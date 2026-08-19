// EmptyState — used wherever a list could be empty. Title, description,
// optional illustration, and an optional CTA.

import { Card, CardBody } from './Card.jsx'

export default function EmptyState({
  icon = null,
  title,
  description,
  action = null,
  className = '',
}) {
  return (
    <Card variant="flat" className={`text-center ${className}`}>
      <CardBody className="py-14">
        {icon && (
          <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-slate-100 to-slate-50 text-slate-400 dark:from-slate-800 dark:to-slate-900 dark:text-slate-500">
            {icon}
          </div>
        )}
        <h3 className="text-base font-semibold text-slate-900 dark:text-slate-100">
          {title}
        </h3>
        {description && (
          <p className="mt-1.5 text-sm text-slate-500 dark:text-slate-400 max-w-md mx-auto">
            {description}
          </p>
        )}
        {action && <div className="mt-5 flex justify-center">{action}</div>}
      </CardBody>
    </Card>
  )
}
