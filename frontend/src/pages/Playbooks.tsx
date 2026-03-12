import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useAuth } from '@/security/AuthContext'
import { Plus, Trash2, Edit, Check, X, Shield, Activity, Workflow } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Spinner } from '@/components/ui/Spinner'
import { getToken } from '@/api/client'
import { toast } from 'sonner'
import { cn } from '@/utils/cn'

interface PlaybookCondition {
    field: string
    operator: 'equals' | 'not_equals' | 'contains' | 'not_contains'
    value: string
}

interface PlaybookAction {
    type: 'set_severity' | 'set_status' | 'add_tag' | 'assign_to'
    value: string
}

interface Playbook {
    id: number
    name: string
    description: string | null
    is_active: boolean
    trigger_type: string
    conditions: PlaybookCondition[]
    actions: PlaybookAction[]
    created_at: string
}

export function Playbooks() {
    const { user } = useAuth()
    const queryClient = useQueryClient()
    const [isEditing, setIsEditing] = useState<number | 'new' | null>(null)

    // Form State
    const [name, setName] = useState('')
    const [description, setDescription] = useState('')
    const [isActive, setIsActive] = useState(true)
    const [conditions, setConditions] = useState<PlaybookCondition[]>([{ field: 'severity', operator: 'equals', value: 'Critical' }])
    const [actions, setActions] = useState<PlaybookAction[]>([{ type: 'set_status', value: 'resolved' }])

    const apiGetPlaybooks = async () => {
        const res = await fetch('/api/v1/playbooks', {
            headers: { Authorization: `Bearer ${getToken()}` },
        })
        if (!res.ok) throw new Error('Failed to fetch playbooks')
        return res.json() as Promise<Playbook[]>
    }

    const playbooksQ = useQuery({ queryKey: ['playbooks'], queryFn: apiGetPlaybooks })

    const updateMutation = useMutation({
        mutationFn: async ({ id, data }: { id: number; data: Partial<Playbook> }) => {
            const res = await fetch(`/api/v1/playbooks/${id}`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
                body: JSON.stringify(data),
            })
            if (!res.ok) throw new Error('Update failed')
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['playbooks'] })
            toast.success('Playbook updated')
        },
        onError: () => toast.error('Failed to update playbook')
    })

    const createMutation = useMutation({
        mutationFn: async (data: Partial<Playbook>) => {
            const res = await fetch('/api/v1/playbooks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` },
                body: JSON.stringify(data),
            })
            if (!res.ok) {
                const err = await res.json().catch(() => ({}))
                throw new Error(err.detail || 'Creation failed')
            }
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['playbooks'] })
            setIsEditing(null)
            toast.success('Playbook created')
        },
        onError: (err: Error) => toast.error(err.message)
    })

    const deleteMutation = useMutation({
        mutationFn: async (id: number) => {
            const res = await fetch(`/api/v1/playbooks/${id}`, {
                method: 'DELETE',
                headers: { Authorization: `Bearer ${getToken()}` },
            })
            if (!res.ok) throw new Error('Delete failed')
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ['playbooks'] })
            toast.success('Playbook deleted')
        },
        onError: () => toast.error('Failed to delete playbook')
    })

    const handleCreateNew = () => {
        setName('')
        setDescription('')
        setIsActive(true)
        setConditions([{ field: 'severity', operator: 'equals', value: 'High' }])
        setActions([{ type: 'set_status', value: 'resolved' }])
        setIsEditing('new')
    }

    const handleEdit = (p: Playbook) => {
        setName(p.name)
        setDescription(p.description || '')
        setIsActive(p.is_active)
        setConditions(p.conditions.length ? p.conditions : [{ field: 'severity', operator: 'equals', value: 'High' }])
        setActions(p.actions.length ? p.actions : [{ type: 'set_status', value: 'resolved' }])
        setIsEditing(p.id)
    }

    const handleSave = () => {
        if (!name.trim()) return toast.error('Name is required')
        if (conditions.length === 0) return toast.error('At least one condition required')
        if (actions.length === 0) return toast.error('At least one action required')

        // validate no empty values
        if (conditions.some(c => !c.value.trim())) return toast.error('Condition values cannot be empty')
        if (actions.some(a => !a.value.trim())) return toast.error('Action values cannot be empty')

        const payload = {
            name,
            description,
            is_active: isActive,
            trigger_type: 'alert_created',
            conditions,
            actions,
        }

        if (isEditing === 'new') {
            createMutation.mutate(payload)
        } else if (typeof isEditing === 'number') {
            updateMutation.mutate({ id: isEditing, data: payload })
            setIsEditing(null)
        }
    }

    if (playbooksQ.isLoading) {
        return (
            <div className="flex h-full items-center justify-center text-soc-muted">
                <Spinner />
            </div>
        )
    }

    const playbooks = playbooksQ.data || []
    const isAdmin = user?.role === 'admin'

    return (
        <div className="space-y-6 max-w-6xl mx-auto">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                        <Workflow className="w-6 h-6 text-blue-400" />
                        Automation Playbooks
                    </h2>
                    <p className="text-soc-muted text-sm mt-1">Configure automated SOAR responses for incoming alerts.</p>
                </div>
                {isAdmin && !isEditing && (
                    <button
                        onClick={handleCreateNew}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium transition-colors"
                    >
                        <Plus className="w-4 h-4" />
                        Create Playbook
                    </button>
                )}
            </div>

            {isEditing && (
                <Card className="border-blue-500/30 shadow-lg shadow-blue-500/5">
                    <CardHeader title={isEditing === 'new' ? 'Create Playbook' : 'Edit Playbook'} />
                    <div className="space-y-6">
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className="block text-sm font-medium text-soc-muted mb-1">Name</label>
                                <input
                                    type="text"
                                    value={name}
                                    onChange={e => setName(e.target.value)}
                                    className="w-full px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none focus:border-blue-500"
                                    placeholder="e.g., Auto-close low severity scans"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-soc-muted mb-1">Description</label>
                                <input
                                    type="text"
                                    value={description}
                                    onChange={e => setDescription(e.target.value)}
                                    className="w-full px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none focus:border-blue-500"
                                />
                            </div>
                        </div>

                        <div className="space-y-3 p-4 border border-soc-border rounded-lg bg-soc-bg/50">
                            <div className="flex items-center justify-between">
                                <h4 className="text-sm font-medium text-soc-text flex items-center gap-2">
                                    <Activity className="w-4 h-4 text-amber-500" /> IF Conditions (AND)
                                </h4>
                                <button
                                    onClick={() => setConditions([...conditions, { field: 'source', operator: 'equals', value: '' }])}
                                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                                >
                                    <Plus className="w-3 h-3" /> Add Condition
                                </button>
                            </div>
                            {conditions.map((cond, idx) => (
                                <div key={idx} className="flex items-center gap-3">
                                    <select
                                        value={cond.field}
                                        onChange={e => {
                                            const newConds = [...conditions];
                                            newConds[idx]!.field = e.target.value;
                                            setConditions(newConds)
                                        }}
                                        className="flex-1 px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none"
                                    >
                                        <option value="severity">Severity</option>
                                        <option value="source">Source</option>
                                        <option value="category">Category</option>
                                        <option value="title">Title</option>
                                        <option value="source_ip">Source IP</option>
                                    </select>
                                    <select
                                        value={cond.operator}
                                        onChange={e => {
                                            const newConds = [...conditions];
                                            newConds[idx]!.operator = e.target.value as any;
                                            setConditions(newConds)
                                        }}
                                        className="w-32 px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none"
                                    >
                                        <option value="equals">Equals</option>
                                        <option value="not_equals">Not Equals</option>
                                        <option value="contains">Contains</option>
                                        <option value="not_contains">Not Contains</option>
                                    </select>
                                    <input
                                        type="text"
                                        value={cond.value}
                                        onChange={e => {
                                            const newConds = [...conditions];
                                            newConds[idx]!.value = e.target.value;
                                            setConditions(newConds)
                                        }}
                                        className="flex-1 px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none focus:border-blue-500"
                                        placeholder="Value..."
                                    />
                                    <button
                                        onClick={() => setConditions(conditions.filter((_, i) => i !== idx))}
                                        className="p-2 text-soc-muted hover:text-red-400"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                        </div>

                        <div className="space-y-3 p-4 border border-soc-border rounded-lg bg-soc-bg/50">
                            <div className="flex items-center justify-between">
                                <h4 className="text-sm font-medium text-soc-text flex items-center gap-2">
                                    <Shield className="w-4 h-4 text-emerald-500" /> THEN Actions
                                </h4>
                                <button
                                    onClick={() => setActions([...actions, { type: 'set_status', value: '' }])}
                                    className="text-xs text-blue-400 hover:text-blue-300 flex items-center gap-1"
                                >
                                    <Plus className="w-3 h-3" /> Add Action
                                </button>
                            </div>
                            {actions.map((act, idx) => (
                                <div key={idx} className="flex items-center gap-3">
                                    <select
                                        value={act.type}
                                        onChange={e => {
                                            const newActs = [...actions];
                                            newActs[idx]!.type = e.target.value as any;
                                            setActions(newActs)
                                        }}
                                        className="w-48 px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none"
                                    >
                                        <option value="set_status">Set Status</option>
                                        <option value="set_severity">Set Severity</option>
                                        <option value="add_tag">Add Tag/Prefix</option>
                                        <option value="assign_to">Assign To User</option>
                                    </select>
                                    <input
                                        type="text"
                                        value={act.value}
                                        onChange={e => {
                                            const newActs = [...actions];
                                            newActs[idx]!.value = e.target.value;
                                            setActions(newActs)
                                        }}
                                        className="flex-1 px-3 py-2 bg-soc-bg border border-soc-border rounded-lg text-soc-text text-sm focus:outline-none focus:border-blue-500"
                                        placeholder="Action value..."
                                    />
                                    <button
                                        onClick={() => setActions(actions.filter((_, i) => i !== idx))}
                                        className="p-2 text-soc-muted hover:text-red-400"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                        </div>

                        <div className="flex items-center justify-between pt-4 border-t border-soc-border">
                            <label className="flex items-center gap-2 cursor-pointer text-sm text-soc-text">
                                <input
                                    type="checkbox"
                                    checked={isActive}
                                    onChange={e => setIsActive(e.target.checked)}
                                    className="w-4 h-4 rounded border-soc-border text-blue-500 focus:ring-blue-500 bg-soc-bg"
                                />
                                Active Playbook
                            </label>
                            <div className="flex gap-3">
                                <button
                                    onClick={() => setIsEditing(null)}
                                    className="px-4 py-2 text-sm text-soc-muted hover:text-soc-text"
                                >
                                    Cancel
                                </button>
                                <button
                                    onClick={handleSave}
                                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-sm font-medium"
                                >
                                    Save Playbook
                                </button>
                            </div>
                        </div>
                    </div>
                </Card>
            )}

            {!isEditing && playbooks.length === 0 && (
                <div className="text-center py-16 border border-soc-border rounded-xl border-dashed">
                    <Workflow className="w-12 h-12 text-soc-border mx-auto mb-4" />
                    <h3 className="text-lg font-medium text-soc-text">No Playbooks</h3>
                    <p className="text-sm text-soc-muted mt-1">Create an automation playbook to automatically triage incoming alerts.</p>
                </div>
            )}

            {!isEditing && playbooks.length > 0 && (
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {playbooks.map((p) => (
                        <Card key={p.id} className={cn("flex flex-col h-full", !p.is_active && "opacity-60")}>
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <div className={cn("w-2 h-2 rounded-full", p.is_active ? "bg-emerald-500" : "bg-soc-border")}></div>
                                    <h3 className="font-semibold text-soc-text truncate" title={p.name}>{p.name}</h3>
                                </div>
                                {isAdmin && (
                                    <div className="flex items-center gap-1">
                                        <button
                                            onClick={() => updateMutation.mutate({ id: p.id, data: { is_active: !p.is_active } })}
                                            className="p-1.5 text-soc-muted hover:bg-soc-border/50 hover:text-soc-text rounded"
                                            title={p.is_active ? "Disable Playbook" : "Enable Playbook"}
                                        >
                                            {p.is_active ? <X className="w-4 h-4" /> : <Check className="w-4 h-4" />}
                                        </button>
                                        <button
                                            onClick={() => handleEdit(p)}
                                            className="p-1.5 text-soc-muted hover:bg-soc-border/50 hover:text-soc-text rounded"
                                            title="Edit Playbook"
                                        >
                                            <Edit className="w-4 h-4" />
                                        </button>
                                        <button
                                            onClick={() => {
                                                if (window.confirm('Delete this playbook?')) deleteMutation.mutate(p.id)
                                            }}
                                            className="p-1.5 text-soc-muted hover:bg-red-500/10 hover:text-red-400 rounded"
                                        >
                                            <Trash2 className="w-4 h-4" />
                                        </button>
                                    </div>
                                )}
                            </div>
                            <p className="text-sm text-soc-muted line-clamp-2 mb-4 flex-1">
                                {p.description || 'No description provided.'}
                            </p>

                            <div className="space-y-2 mt-auto pt-4 border-t border-soc-border text-xs">
                                <div className="flex items-center justify-between text-soc-muted">
                                    <span>Conditions</span>
                                    <span className="px-2 py-0.5 rounded bg-soc-bg border border-soc-border">{p.conditions.length}</span>
                                </div>
                                <div className="flex items-center justify-between text-soc-muted">
                                    <span>Actions</span>
                                    <span className="px-2 py-0.5 rounded bg-soc-bg border border-soc-border text-blue-400">{p.actions.length}</span>
                                </div>
                            </div>
                        </Card>
                    ))}
                </div>
            )}
        </div>
    )
}
