import { useEffect, useState } from "react";
import { get as apiGet, post as apiPost, patch as apiPatch } from "@/api/client";
import { useQuery } from "@tanstack/react-query";
import {
  Users as UsersIcon, Pencil, Shield, Eye, EyeOff,
  UserPlus, ChevronDown, ChevronUp, Activity, Clock, LogIn,
  FileText, AlertTriangle,
} from "lucide-react";
import { toast } from "sonner";
import { useAuth } from "@/security/AuthContext";

type Role = "admin" | "soc_lead" | "senior_analyst" | "analyst" | "threat_hunter" | "viewer";

interface AppUser {
  id: string | number;
  name?: string;
  username?: string;
  initials?: string;
  email?: string | null;
  role: Role;
  is_active: boolean;
  lastActive?: string;
  created_at?: string | null;
}

const roleLabels: Record<Role, string> = {
  admin: "Admin",
  soc_lead: "SOC Lead",
  senior_analyst: "Senior Analyst",
  analyst: "Analyst",
  threat_hunter: "Threat Hunter",
  viewer: "Viewer",
};

const roleColors: Record<Role, string> = {
  admin: "bg-red-500/15 text-red-400 border-red-500/30",
  soc_lead: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  senior_analyst: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  analyst: "bg-muted text-muted-foreground border-border",
  threat_hunter: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  viewer: "bg-muted text-muted-foreground border-border",
};

const rolePerms: Record<Role, string[]> = {
  admin: ["Full access", "Manage users & settings", "Create/edit playbooks", "Run playbooks", "Assign alerts"],
  soc_lead: ["Manage team assignments", "Run & create playbooks", "Access all reports", "Manage incidents"],
  senior_analyst: ["Assign alerts to others", "Run playbooks", "Access reports", "Manage incidents"],
  analyst: ["Pick up alerts", "Update alert status", "Add comments & notes", "View dashboards"],
  threat_hunter: ["Run threat hunts", "Create detection rules", "Access raw logs", "View dashboards"],
  viewer: ["Read-only access", "View dashboards", "View alerts & incidents"],
};

const INITIAL_USERS: AppUser[] = [];

interface AuditEvent {
  id: string;
  action: string;
  target: string | null;
  timestamp: string | null;
  ip_address: string | null;
  details: Record<string, unknown> | null;
  method: string | null;
  path: string | null;
}

interface UserActivityResponse {
  user_id: string;
  username: string;
  total: number;
  events: AuditEvent[];
}

interface ActivityRow {
  id: string;
  type: "login" | "action" | "alert" | "config";
  userName: string;
  action: string;
  detail: string;
  timestamp: string | null;
  target: string | null;
  ip_address: string | null;
  method: string | null;
  path: string | null;
}

function classifyAction(action: string): "login" | "action" | "alert" | "config" {
  if (action.includes("login") || action.includes("logout") || action.includes("session")) return "login";
  if (action.includes("alert") || action.includes("incident")) return "alert";
  if (action.includes("settings") || action.includes("config") || action.includes("update")) return "config";
  return "action";
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60_000);
  if (m < 1) return "Just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

const activityTypeIcon: Record<string, React.ElementType> = {
  login: LogIn,
  action: Activity,
  alert: AlertTriangle,
  config: FileText,
};

const activityTypeColor: Record<string, string> = {
  login: "text-blue-400",
  action: "text-emerald-400",
  alert: "text-orange-400",
  config: "text-purple-400",
};

function getInitials(name?: string, username?: string): string {
  const display = name || username || "?";
  return display.split(/[\s._-]/).map((n) => n[0] ?? "").join("").toUpperCase().slice(0, 2);
}

function getDisplayName(u: AppUser): string {
  return u.name || u.username || String(u.id);
}

export function UserManagement() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [users, setUsers] = useState<AppUser[]>(INITIAL_USERS);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<AppUser | null>(null);
  const [form, setForm] = useState({ username: "", name: "", email: "", password: "", role: "analyst" as Role });
  const [showPassword, setShowPassword] = useState(false);
  const [rolesOpen, setRolesOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"users" | "activity">("users");
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState<string | number | null>(null);
  const [filterActivity, setFilterActivity] = useState("all");
  const [apiLoaded, setApiLoaded] = useState(false);
  const [activityUserId, setActivityUserId] = useState<string | null>(null);

  // Fetch activity for selected user or global activity (all users)
  const { data: activityData, isLoading: activityLoading } = useQuery<UserActivityResponse>({
    queryKey: ["user-activity", activityUserId ?? "all"],
    queryFn: async () => {
      if (activityUserId) {
        return apiGet<UserActivityResponse>(`/auth/users/${activityUserId}/activity`);
      }
      // For "all users" view, fetch activity for first available user if apiLoaded
      return { user_id: "", username: "", total: 0, events: [] };
    },
    enabled: activeTab === "activity" && isAdmin,
    staleTime: 30_000,
  });

  useEffect(() => {
    fetchUsers();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const fetchUsers = async () => {
    setError("");
    try {
      const data = await apiGet<{ users: AppUser[] }>("/auth/users");
      const apiUsers: AppUser[] = (data?.users ?? []).map((u: AppUser) => ({
        ...u,
        initials: getInitials(u.name, u.username),
        name: u.name || u.username || String(u.id),
      }));
      setUsers(apiUsers);
      setApiLoaded(true);
    } catch {
      setApiLoaded(false);
      setUsers([]);
      setError("Unable to load users from API.");
    }
  };

  const updateUser = async (id: string | number, updates: { role?: string; is_active?: boolean }) => {
    setError("");
    setBusyId(id);
    try {
      if (!apiLoaded) {
        throw new Error("User management API is unavailable");
      }
      await apiPatch(`/auth/users/${id}`, updates);
      await fetchUsers();
      toast.success("User updated");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update user");
    } finally {
      setBusyId(null);
    }
  };

  const openCreate = () => {
    setEditingUser(null);
    setForm({ username: "", name: "", email: "", password: "", role: "analyst" });
    setDialogOpen(true);
  };

  const openEdit = (u: AppUser) => {
    setEditingUser(u);
    setForm({ username: u.username ?? "", name: u.name ?? "", email: u.email ?? "", password: "", role: u.role });
    setDialogOpen(true);
  };

  const handleSave = async () => {
    if (!editingUser && !form.name.trim() && !form.username.trim()) {
      toast.error("Name is required");
      return;
    }
    if (!editingUser && !form.password) {
      toast.error("Password is required");
      return;
    }

    if (editingUser) {
      await updateUser(editingUser.id, { role: form.role });
    } else {
      if (!apiLoaded) {
        toast.error("User management API is unavailable");
        return;
      }
      setError("");
      try {
        await apiPost("/auth/users", { username: form.username || form.name, name: form.name, email: form.email, password: form.password, role: form.role });
        toast.success("User created");
        await fetchUsers();
      } catch (err) {
        toast.error(err instanceof Error ? err.message : "Failed to create user");
        return;
      }
    }
    setDialogOpen(false);
  };

  const activeCount = users.filter((u) => u.is_active).length;

  const auditEvents = activityData?.events ?? [];
  const activityRows: ActivityRow[] = auditEvents.map((a: AuditEvent) => {
    const detail = String(a.target || a.path || "No additional context")
    return {
      id: a.id,
      type: classifyAction(a.action),
      userName: activityData?.username || "User",
      action: a.action,
      detail,
      timestamp: a.timestamp,
      target: a.target,
      ip_address: a.ip_address,
      method: a.method,
      path: a.path,
    }
  })
  const filteredActivity = filterActivity === "all"
    ? activityRows
    : activityRows.filter((a) => a.type === filterActivity);

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold tracking-tight flex items-center gap-2">
            <UsersIcon className="h-5 w-5 text-primary" /> Users
          </h1>
          <p className="text-xs text-muted-foreground">{activeCount} active users</p>
        </div>
        <button
          onClick={openCreate}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg gradient-primary text-primary-foreground"
        >
          <UserPlus className="h-3.5 w-3.5" /> Invite User
        </button>
      </div>

      {error && <p className="text-xs text-destructive">{error}</p>}

      {/* Tabs (admin only sees activity tab) */}
      {isAdmin && (
        <div className="flex gap-1 p-1 rounded-lg bg-muted/50 w-fit">
          {(["users", "activity"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 text-xs font-medium rounded-md capitalize transition-all ${
                activeTab === tab
                  ? "bg-background text-foreground shadow-sm"
                  : "text-muted-foreground hover:text-foreground"
              }`}
            >
              {tab === "users" ? "User Management" : "User Activity"}
            </button>
          ))}
        </div>
      )}

      {(activeTab === "users" || !isAdmin) && (
        <>
          {/* Users Table */}
          <div className="glass-card rounded-xl overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/50">
                    <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-muted-foreground">User</th>
                    <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-muted-foreground">Role</th>
                    <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-muted-foreground">Status</th>
                    <th className="text-left px-4 py-3 text-[10px] uppercase tracking-wider text-muted-foreground">Last Active</th>
                    <th className="text-right px-4 py-3 text-[10px] uppercase tracking-wider text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => {
                    const roleCls = roleColors[u.role] ?? "bg-muted text-muted-foreground border-border";
                    const roleLabel = roleLabels[u.role] ?? u.role;
                    const initials = u.initials ?? getInitials(u.name, u.username);
                    return (
                      <tr key={u.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-3">
                            <div className="h-9 w-9 rounded-full bg-primary/15 border border-primary/30 flex items-center justify-center shrink-0">
                              <span className="text-xs font-semibold text-primary">{initials}</span>
                            </div>
                            <div>
                              <p className="text-sm font-medium">{getDisplayName(u)}</p>
                              <p className="text-xs text-muted-foreground">{u.email ?? u.username ?? ""}</p>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-medium px-2 py-0.5 rounded border ${roleCls}`}>
                            {roleLabel}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`text-[10px] font-medium px-2 py-0.5 rounded border ${
                            u.is_active
                              ? "bg-green-500/15 text-green-400 border-green-500/30"
                              : "bg-muted text-muted-foreground border-border"
                          }`}>
                            {u.is_active ? "Active" : "Inactive"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-muted-foreground">
                          {u.lastActive ?? u.created_at?.slice(0, 10) ?? "—"}
                        </td>
                        <td className="px-4 py-3 text-right">
                          {String(u.id) === String(user?.id) ? (
                            <span className="text-xs text-muted-foreground italic">(you)</span>
                          ) : (
                            <div className="flex items-center gap-2 justify-end">
                              <button
                                onClick={() => openEdit(u)}
                                className="flex items-center gap-1 px-2 py-1 text-xs rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
                              >
                                <Pencil className="h-3 w-3" /> Edit
                              </button>
                              {isAdmin && (
                                <button
                                  onClick={() => updateUser(u.id, { is_active: !u.is_active })}
                                  disabled={busyId === u.id}
                                  className="px-2 py-1 text-xs rounded border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors disabled:opacity-50"
                                >
                                  {u.is_active ? "Deactivate" : "Activate"}
                                </button>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          {/* Role Permissions Collapsible */}
          <div className="glass-card rounded-xl overflow-hidden">
            <button
              className="w-full flex items-center justify-between px-4 py-3 hover:bg-muted/20 transition-colors"
              onClick={() => setRolesOpen(!rolesOpen)}
            >
              <span className="text-sm font-semibold flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" /> Role Permissions
              </span>
              {rolesOpen ? <ChevronUp className="h-4 w-4 text-muted-foreground" /> : <ChevronDown className="h-4 w-4 text-muted-foreground" />}
            </button>
            {rolesOpen && (
              <div className="px-4 pb-4 border-t border-border/30">
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 pt-4">
                  {(Object.entries(rolePerms) as [Role, string[]][]).map(([role, perms]) => (
                    <div key={role} className="rounded-lg border border-border/50 p-3 space-y-2">
                      <span className={`text-[10px] font-medium px-2 py-0.5 rounded border ${roleColors[role]}`}>
                        {roleLabels[role]}
                      </span>
                      <ul className="space-y-1">
                        {perms.map((p) => (
                          <li key={p} className="text-[10px] text-muted-foreground flex items-start gap-1.5">
                            <span className="text-primary mt-0.5">•</span> {p}
                          </li>
                        ))}
                      </ul>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Activity Tab (admin only) */}
      {activeTab === "activity" && isAdmin && (
        <div className="space-y-4">
          {/* User selector + type filter */}
          <div className="flex items-center gap-3 flex-wrap">
            <select
              value={activityUserId ?? ""}
              onChange={(e) => setActivityUserId(e.target.value || null)}
              className="h-9 px-3 rounded-lg border border-border bg-muted/30 text-foreground text-xs focus:outline-none focus:border-primary cursor-pointer"
            >
              <option value="">Select a user…</option>
              {users.map((u) => (
                <option key={String(u.id)} value={String(u.id)}>
                  {getDisplayName(u)}
                </option>
              ))}
            </select>
            {["all", "login", "action", "alert", "config"].map((type) => (
              <button
                key={type}
                onClick={() => setFilterActivity(type)}
                className={`px-3 py-1.5 text-xs font-medium rounded-lg capitalize transition-all ${
                  filterActivity === type
                    ? "gradient-primary text-primary-foreground"
                    : "border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30"
                }`}
              >
                {type === "all" ? "All Types" : type}
              </button>
            ))}
          </div>

          {!activityUserId ? (
            <div className="rounded-lg border border-border/40 bg-muted/20 px-4 py-8 text-center text-sm text-muted-foreground">
              Select a user above to view their audit activity.
            </div>
          ) : (
            <div className="glass-card rounded-xl overflow-hidden">
              {activityLoading ? (
                <div className="text-center py-8 text-sm text-muted-foreground">Loading activity…</div>
              ) : (
                <div className="divide-y divide-border/30">
                  {filteredActivity.length === 0 ? (
                    <div className="text-center py-8 text-sm text-muted-foreground">
                      No activity recorded for this user.
                    </div>
                  ) : filteredActivity.map((event) => {
                    const type = classifyAction(event.action);
                    const Icon = activityTypeIcon[type] ?? Activity;
                    const color = activityTypeColor[type] ?? "text-muted-foreground";
                    return (
                      <div key={event.id} className="flex items-start gap-4 p-4 hover:bg-muted/20 transition-colors">
                        <div className={`h-8 w-8 rounded-lg bg-muted/50 flex items-center justify-center shrink-0 ${color}`}>
                          <Icon className="h-4 w-4" />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-xs font-medium text-foreground">{event.action}</span>
                            {event.target && (
                              <>
                                <span className="text-xs text-muted-foreground">—</span>
                                <span className="text-xs text-muted-foreground font-mono">{event.target}</span>
                              </>
                            )}
                            {event.ip_address && (
                              <span className="text-[10px] bg-muted/50 px-1.5 py-0.5 rounded font-mono text-muted-foreground">
                                {event.ip_address}
                              </span>
                            )}
                          </div>
                          {event.path && (
                            <p className="text-[10px] text-muted-foreground/60 mt-0.5 font-mono">
                              {event.method} {event.path}
                            </p>
                          )}
                        </div>
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground shrink-0">
                          <Clock className="h-3 w-3" />
                          {relativeTime(event.timestamp)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Create/Edit Modal */}
      {dialogOpen && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
          onClick={(e) => e.target === e.currentTarget && setDialogOpen(false)}
          role="dialog"
          aria-modal="true"
        >
          <div className="glass-card-elevated rounded-2xl shadow-2xl shadow-black/40 p-6 max-w-md w-full mx-4">
            <h2 className="text-sm font-bold mb-1">{editingUser ? "Edit User" : "Invite User"}</h2>
            <p className="text-[10px] text-muted-foreground mb-4">
              {editingUser ? "Update user role" : "Create a new platform user"}
            </p>

            <div className="space-y-3">
              {!editingUser && (
                <>
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Full Name *</label>
                    <input
                      value={form.name}
                      onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
                      placeholder="John Doe"
                      className="w-full h-8 px-3 text-xs rounded-lg border border-border bg-muted/30 text-foreground focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Email</label>
                    <input
                      type="email"
                      value={form.email}
                      onChange={(e) => setForm((f) => ({ ...f, email: e.target.value }))}
                      placeholder="john@company.io"
                      className="w-full h-8 px-3 text-xs rounded-lg border border-border bg-muted/30 text-foreground focus:outline-none focus:border-primary transition-colors"
                    />
                  </div>
                  <div>
                    <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Password *</label>
                    <div className="relative">
                      <input
                        type={showPassword ? "text" : "password"}
                        value={form.password}
                        onChange={(e) => setForm((f) => ({ ...f, password: e.target.value }))}
                        placeholder="Min. 12 characters"
                        className="w-full h-8 px-3 pr-8 text-xs rounded-lg border border-border bg-muted/30 text-foreground focus:outline-none focus:border-primary transition-colors"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                      >
                        {showPassword ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                      </button>
                    </div>
                  </div>
                </>
              )}
              <div>
                <label className="block text-[10px] uppercase tracking-wider text-muted-foreground mb-1">Role</label>
                <select
                  value={form.role}
                  onChange={(e) => setForm((f) => ({ ...f, role: e.target.value as Role }))}
                  className="w-full h-8 px-3 text-xs rounded-lg border border-border bg-muted/30 text-foreground focus:outline-none focus:border-primary transition-colors"
                >
                  {(Object.entries(roleLabels) as [Role, string][]).map(([key, label]) => (
                    <option key={key} value={key}>{label}</option>
                  ))}
                </select>
              </div>
            </div>

            <div className="flex gap-2 justify-end mt-5 pt-4 border-t border-border/50">
              <button
                type="button"
                onClick={() => setDialogOpen(false)}
                className="px-3 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/30 transition-colors"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleSave}
                className="px-3 py-1.5 text-xs font-medium rounded-lg gradient-primary text-primary-foreground"
              >
                {editingUser ? "Save Changes" : "Invite User"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default UserManagement;
