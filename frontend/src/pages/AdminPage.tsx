import { ShieldCheck, Trash2 } from 'lucide-react'
import { useAuth } from '../auth/AuthContext'

/**
 * Administration page — reachable only via RequireAdmin (backend enforces
 * the same role on admin-only endpoints with 403 for analysts).
 */
export function AdminPage() {
  const { user } = useAuth()

  return (
    <div className="p-8">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold text-fg">Administration</h1>
        <p className="mt-1 text-sm text-fg-subtle">
          Identity, role mapping, and administration-only operations.
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Current identity */}
        <section className="rounded-xl border border-border bg-surface-2/50 p-6">
          <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-fg-subtle">
            <ShieldCheck size={16} aria-hidden /> Current identity
          </h2>
          <dl className="mt-4 grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2 text-sm">
            <dt className="text-fg-subtle">Username</dt>
            <dd className="font-medium text-fg">{user?.username ?? '—'}</dd>
            <dt className="text-fg-subtle">Subject</dt>
            <dd className="font-mono text-xs leading-6 text-fg">{user?.sub ?? '—'}</dd>
            <dt className="text-fg-subtle">Email</dt>
            <dd className="font-medium text-fg">{user?.email ?? '—'}</dd>
            <dt className="text-fg-subtle">Groups</dt>
            <dd className="font-mono text-xs leading-6 text-fg">{user?.groups.join(', ') || '—'}</dd>
          </dl>
        </section>

        {/* Role mapping */}
        <section className="rounded-xl border border-border bg-surface-2/50 p-6">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-fg-subtle">
            Role mapping
          </h2>
          <table className="mt-4 w-full text-sm">
            <thead>
              <tr className="text-left text-xs uppercase tracking-wider text-fg-subtle">
                <th className="pb-2 pr-4">Authentik group</th>
                <th className="pb-2">Granted role</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              <tr>
                <td className="py-2 font-mono text-xs">packetkage-admin</td>
                <td className="text-fg">
                  Admin — full access, including <code className="text-xs">DELETE</code> of
                  captures and cases
                </td>
              </tr>
              <tr>
                <td className="py-2 font-mono text-xs">packetkage-analyst</td>
                <td className="text-fg">Analyst — read, analyze, investigate</td>
              </tr>
            </tbody>
          </table>
        </section>
      </div>

      {/* Admin-only operations */}
      <section className="mt-4 rounded-xl border border-border bg-surface-2/50 p-6">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wider text-fg-subtle">
          <Trash2 size={16} aria-hidden /> Admin-only operations
        </h2>
        <ul className="mt-3 list-inside list-disc space-y-1 text-sm text-fg-muted">
          <li>
            Delete captures — permanently removes the stored PCAP and every derived analysis row.
          </li>
          <li>
            Delete cases — permanently removes a case. Both are enforced server-side: analysts
            receive <code className="text-xs">403 Forbidden</code>.
          </li>
        </ul>
      </section>
    </div>
  )
}