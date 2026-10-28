import { useEffect, useState } from 'react'
import PageHeader from '../components/PageHeader.jsx'
import Card from '../components/Card.jsx'
import Button from '../components/Button.jsx'
import Modal from '../components/Modal.jsx'
import Spinner from '../components/Spinner.jsx'
import EmptyState from '../components/EmptyState.jsx'
import { institutions as instApi } from '../services/api.js'
import { formatDateTime, formatError } from '../utils/format.jsx'
import toast from 'react-hot-toast'

export default function InstitutionsPage() {
  const [institutionsList, setInstitutionsList] = useState([])
  const [loading, setLoading] = useState(true)
  const [modalOpen, setModalOpen] = useState(false)
  const [name, setName] = useState('')
  const [slug, setSlug] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const fetchInstitutions = async () => {
    try {
      setLoading(true)
      const res = await instApi.list()
      setInstitutionsList(res || [])
    } catch {
      toast.error('Failed to load institutions')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchInstitutions()
  }, [])

  const handleCreate = async (e) => {
    e.preventDefault()
    try {
      setSubmitting(true)
      await instApi.create({ name: name.trim(), slug: slug.trim().toLowerCase() })
      toast.success('Institution created successfully')
      setName('')
      setSlug('')
      setModalOpen(false)
      fetchInstitutions()
    } catch (err) {
      toast.error(formatError(err, 'Failed to create institution'))
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Institution Management"
        description="Multi-tenant institutional partitions, isolated asset catalogues, and global vulnerability governance."
        action={
          <Button variant="primary" onClick={() => setModalOpen(true)}>
            + New Institution
          </Button>
        }
      />

      <Card>
        {loading ? (
          <div className="p-12 flex justify-center"><Spinner size="lg" /></div>
        ) : institutionsList.length === 0 ? (
          <EmptyState
            title="No institutions registered"
            description="Create an institutional partition to begin onboarding assets and users."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-slate-50 dark:bg-slate-800/60 text-xs font-semibold text-slate-500 uppercase tracking-wider border-b border-slate-200 dark:border-slate-800">
                <tr>
                  <th className="px-4 py-3">Tenant ID</th>
                  <th className="px-4 py-3">Institution Name</th>
                  <th className="px-4 py-3">Slug</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Created At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {institutionsList.map((inst) => (
                  <tr key={inst.id} className="hover:bg-slate-50/60 dark:hover:bg-slate-800/40">
                    <td className="px-4 py-3.5 font-mono text-xs text-slate-500">#{inst.id}</td>
                    <td className="px-4 py-3.5 font-semibold text-slate-900 dark:text-slate-100">{inst.name}</td>
                    <td className="px-4 py-3.5 font-mono text-xs text-brand-600">{inst.slug}</td>
                    <td className="px-4 py-3.5">
                      <span className="inline-flex px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                        Active Tenant
                      </span>
                    </td>
                    <td className="px-4 py-3.5 text-xs text-slate-500">
                      {formatDateTime(inst.created_at)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Modal open={modalOpen} onClose={() => setModalOpen(false)} title="Create Institution Tenant">
        <form onSubmit={handleCreate} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold uppercase text-slate-700 dark:text-slate-300 mb-1">
              Institution Name
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => {
                setName(e.target.value)
                if (!slug) setSlug(e.target.value.toLowerCase().replace(/[^a-z0-9]/g, '-'))
              }}
              placeholder="e.g. Stanford University"
              className="w-full text-sm rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase text-slate-700 dark:text-slate-300 mb-1">
              Tenant Slug (Unique URL identifier)
            </label>
            <input
              type="text"
              required
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="e.g. stanford-university"
              className="w-full text-sm font-mono rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-brand-500"
            />
          </div>

          <div className="pt-4 flex justify-end gap-2 border-t border-slate-200 dark:border-slate-800">
            <Button variant="ghost" onClick={() => setModalOpen(false)} type="button">
              Cancel
            </Button>
            <Button variant="primary" type="submit" disabled={submitting}>
              {submitting ? 'Creating…' : 'Create Institution'}
            </Button>
          </div>
        </form>
      </Modal>
    </div>
  )
}
