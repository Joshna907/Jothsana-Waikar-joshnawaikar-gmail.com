import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  ActivityIcon,
  CaretDown,
  CheckCircle,
  CircleNotch,
  Desktop,
  FileArrowUp,
  GearSix,
  Key,
  Laptop,
  List,
  Monitor,
  Plus,
  ShieldCheck,
  SignOut,
  Terminal,
  Users,
  X,
} from "@phosphor-icons/react";
import { api, clearToken, setToken } from "./api.js";
import "./styles.css";

const nav = [
  ["devices", "Devices", "device:list", Monitor],
  ["people", "People", "user:read", Users],
  ["grants", "Access grants", "user:read", Key],
  ["sessions", "Sessions", "session:view", ActivityIcon],
  ["audit", "Audit trail", "audit:read", List],
  ["admin", "Organization", ["org:update", "org:delete"], GearSix],
];
const deviceActions = [
  ["device:view", "View", Desktop, "view", "start-view"],
  ["device:control", "Control", Monitor, "control", "start-control"],
  ["device:terminal", "Terminal", Terminal, "terminal", "start-terminal"],
  [
    "device:file_transfer",
    "Transfer files",
    FileArrowUp,
    null,
    "transfer-files",
  ],
];
const can = (p, key) => p?.[key]?.effect === "allow";
const allowed = (p, need) =>
  Array.isArray(need) ? need.some((key) => can(p, key)) : can(p, need);
const friendlyDate = (value) =>
  value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(new Date(value))
    : "No expiry";
const errorText = (e) => e?.message || "The request could not be completed.";

function Gate({ permission, testId, className = "", children, onClick }) {
  return (
    <button
      type="button"
      data-testid={testId}
      data-permission={permission}
      data-state="unlocked"
      className={`action ${className}`}
      onClick={onClick}
    >
      {children}
    </button>
  );
}
function Loading({ label = "Loading workspace" }) {
  return (
    <main className="loading">
      <CircleNotch className="spin" size={23} />
      {label}
    </main>
  );
}
function Notice({ text, close }) {
  return (
    text && (
      <div className="notice" role="status">
        {text}
        <button aria-label="Dismiss message" onClick={close}>
          <X size={16} />
        </button>
      </div>
    )
  );
}
function Empty({ title, text, testId }) {
  return (
    <div className="empty" data-testid={testId}>
      <ShieldCheck size={28} />
      <h2>{title}</h2>
      <p>{text}</p>
    </div>
  );
}
function Skeleton({ count = 4 }) {
  return (
    <div className="skeletons">
      {Array.from({ length: count }, (_, i) => (
        <div className="skeleton" key={i} />
      ))}
    </div>
  );
}
function Modal({ title, close, children }) {
  const dialog = useRef(null);
  useEffect(() => {
    const previous = document.activeElement;
    const focusable = dialog.current?.querySelector(
      'input, select, button, [tabindex]:not([tabindex="-1"])',
    );
    (focusable || dialog.current)?.focus();
    const onKeyDown = (event) => {
      if (event.key === "Escape") close();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      previous?.focus?.();
    };
  }, [close]);
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) close();
      }}
    >
      <section
        ref={dialog}
        tabIndex={-1}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
      >
        <header>
          <h2 id="dialog-title">{title}</h2>
          <button
            type="button"
            className="icon-button"
            aria-label="Close dialog"
            onClick={close}
          >
            <X size={18} />
          </button>
        </header>
        {children}
      </section>
    </div>
  );
}

function Login({ done }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  async function submit(e) {
    e.preventDefault();
    if (!email || !password)
      return setError({
        code: "MISSING_CREDENTIALS",
        text: "Email and password are required.",
      });
    setBusy(true);
    setError(null);
    try {
      const r = await api("/v1/auth/login", {
        method: "POST",
        auth: false,
        body: { email, password },
      });
      setToken(r.token);
      done(r);
    } catch (err) {
      setError({ code: err.code || "UNAUTHENTICATED", text: errorText(err) });
    } finally {
      setBusy(false);
    }
  }
  return (
    <main id="main-content" className="auth-page">
      <section className="auth-intro">
        <div className="wordmark">
          RemoteOps<span>./</span>
        </div>
        <p className="eyebrow">Command center</p>
        <h1>
          Permission clarity
          <br />
          for every machine.
        </h1>
        <p className="auth-copy">
          A focused multi-organization console for device access, people, and
          remote work.
        </p>
        <div className="auth-rule">
          <ShieldCheck size={18} />
          Server-resolved authority
        </div>
      </section>
      <section className="login-panel">
        <form data-testid="login-form" className="login-form" onSubmit={submit}>
          <div>
            <p className="eyebrow">Sign in</p>
            <h2>Welcome back</h2>
            <p>
              Use a demo account to explore how each role changes the workspace.
            </p>
          </div>
          {error && (
            <div
              data-testid="login-error"
              data-error-code={error.code}
              className="form-error"
              role="alert"
            >
              {error.text}
            </div>
          )}
          <label>
            Email
            <input
              name="email"
              data-testid="login-email"
              type="email"
              autoComplete="email"
              spellCheck={false}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>
          <label>
            Password
            <input
              name="password"
              data-testid="login-password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          <button
            data-testid="login-submit"
            className="primary wide"
            disabled={busy}
          >
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="demo-copy">Try dana@example.test / demo1234</p>
        </form>
      </section>
    </main>
  );
}

function Invite({ token, done }) {
  const [invite, setInvite] = useState(null);
  const [error, setError] = useState(null);
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  useEffect(() => {
    api(`/v1/invites/${token}`, { auth: false })
      .then(setInvite)
      .catch((e) => setError(errorText(e)));
  }, [token]);
  async function submit(e) {
    e.preventDefault();
    try {
      await api(`/v1/invites/${token}/accept`, {
        method: "POST",
        auth: false,
        body: { name, password },
      });
      done();
    } catch (err) {
      setError(errorText(err));
    }
  }
  if (error && !invite)
    return (
      <main className="invite-page">
        <section className="invite-card">
          <h1>Invitation unavailable</h1>
          <p data-testid="invite-error" role="alert">
            {error}
          </p>
        </section>
      </main>
    );
  if (!invite) return <Loading label="Checking invitation" />;
  return (
    <main id="main-content" className="invite-page">
      <section className="invite-card">
        <div className="wordmark">
          RemoteOps<span>./</span>
        </div>
        <p className="eyebrow">Organization invitation</p>
        <h1>Join {invite.orgName}</h1>
        <p>
          You have been invited as{" "}
          <strong data-testid="invite-role">{invite.role}</strong>.
        </p>
        <form className="stack-form" onSubmit={submit}>
          <label>
            Email
            <input
              name="email"
              data-testid="invite-email"
              autoComplete="email"
              spellCheck={false}
              readOnly
              value={invite.email}
            />
          </label>
          <label>
            Your name
            <input
              name="name"
              data-testid="invite-name"
              autoComplete="name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </label>
          <label>
            Create password
            <input
              name="new-password"
              data-testid="invite-password"
              type="password"
              autoComplete="new-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
          </label>
          {error && (
            <div className="form-error" role="alert">
              {error}
            </div>
          )}
          <button data-testid="invite-submit" className="primary wide">
            Join organization
          </button>
        </form>
      </section>
    </main>
  );
}

function App() {
  const [session, setSession] = useState(null);
  const [loading, setLoading] = useState(true);
  const [path, setPath] = useState(location.pathname);
  const inviteAccepted = useRef(false);
  useEffect(() => {
    if (path.startsWith("/invite/")) return setLoading(false);
    if (inviteAccepted.current) {
      inviteAccepted.current = false;
      setLoading(false);
      return;
    }
    api("/v1/auth/refresh", { method: "POST", auth: false, body: {} })
      .then((r) => {
        setToken(r.token);
        setSession(r);
      })
      .catch(clearToken)
      .finally(() => setLoading(false));
  }, [path]);
  if (path.startsWith("/invite/"))
    return (
      <Invite
        token={path.split("/").pop()}
        done={() => {
          inviteAccepted.current = true;
          history.replaceState({}, "", "/");
          setPath("/");
        }}
      />
    );
  if (loading) return <Loading />;
  return session ? (
    <Console
      session={session}
      setSession={setSession}
      signOut={async () => {
        try {
          await api("/v1/auth/refresh/logout", {
            method: "POST",
            auth: false,
            body: {},
          });
        } finally {
          clearToken();
          setSession(null);
        }
      }}
    />
  ) : (
    <Login done={setSession} />
  );
}

function Console({ session, setSession, signOut }) {
  const [me, setMe] = useState({
    user: session.user,
    orgId: session.orgId,
    role: session.role,
    orgs: session.orgs,
    roles: session.roles || [],
    permissions: session.permissions,
  });
  const [view, setView] = useState("devices");
  const [notice, setNotice] = useState(null);
  const org = me.orgs.find((entry) => entry.id === me.orgId) || me.orgs[0];
  useEffect(() => {
    api("/v1/auth/me")
      .then(setMe)
      .catch((e) => setNotice(errorText(e)));
  }, [session.token]);
  async function switchOrg(id) {
    try {
      const next = await api("/v1/auth/token", {
        method: "POST",
        body: { orgId: id },
      });
      setToken(next.token);
      setSession((old) => ({ ...old, ...next }));
      setMe(await api("/v1/auth/me"));
      setView("devices");
    } catch (e) {
      setNotice(errorText(e));
    }
  }
  async function createOrg() {
    const name = window.prompt("Name the new organization");
    if (!name?.trim()) return;
    try {
      const created = await api("/v1/orgs", {
        method: "POST",
        body: { name: name.trim() },
      });
      await switchOrg(created.id);
    } catch (e) {
      setNotice(errorText(e));
    }
  }
  return (
    <div
      data-testid="app-shell"
      data-org-id={me.orgId}
      data-org-theme={org?.theme || "cobalt"}
      className="app-shell"
    >
      <aside className="sidebar">
        <div className="wordmark">
          RemoteOps<span>./</span>
        </div>
        <div className="org-picker">
          <div className="org-trigger" aria-label="Active organization">
            <span className="org-mark">{org?.name?.[0]}</span>
            <span>
              <strong>{org?.name}</strong>
              <small>
                <span data-testid="active-role">{me.role}</span> access
              </small>
            </span>
          </div>
          <div
            className="org-menu org-menu-static"
            role="group"
            aria-label="Organizations"
          >
            {me.orgs.map((entry) => (
              <button
                type="button"
                key={entry.id}
                data-testid="org-option"
                data-org-id={entry.id}
                onClick={() => switchOrg(entry.id)}
                className={entry.id === me.orgId ? "selected" : ""}
              >
                <span className="org-mark">{entry.name[0]}</span>
                <span>
                  {entry.name}
                  <small>{entry.role}</small>
                </span>
                {entry.id === me.orgId && <CheckCircle size={15} />}
              </button>
            ))}
            <button
              type="button"
              data-testid="create-org"
              className="create-org"
              onClick={createOrg}
            >
              <Plus size={16} />
              Create organization
            </button>
          </div>
        </div>
        <nav aria-label="Workspace">
          {nav
            .filter(([, , permission]) => allowed(me.permissions, permission))
            .map(([key, label, permission, Icon]) => (
              <button
                type="button"
                key={key}
                data-testid={`nav-${key}`}
                data-permission={
                  Array.isArray(permission) ? permission.join("|") : permission
                }
                data-state="unlocked"
                aria-current={view === key ? "page" : undefined}
                className={`nav-item ${view === key ? "active" : ""}`}
                onClick={() => {
                  setView(key);
                  setNotice(null);
                }}
              >
                <Icon size={19} weight={view === key ? "fill" : "regular"} />
                {label}
              </button>
            ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="identity">
            <span>
              {me.user?.name
                ?.split(" ")
                .map((part) => part[0])
                .join("")
                .slice(0, 2)}
            </span>
            <div>
              <strong>{me.user?.name}</strong>
              <small>{me.user?.email}</small>
            </div>
          </div>
          <button type="button" className="sign-out" onClick={signOut}>
            <SignOut size={18} />
            Sign out
          </button>
        </div>
      </aside>
      <main id="main-content" className="workspace">
        <header className="workspace-header">
          <div>
            <p className="eyebrow">{org?.name}</p>
            <h1>{nav.find(([key]) => key === view)?.[1]}</h1>
          </div>
          <div className="header-status">
            <span />
            Secure session
          </div>
        </header>
        <Notice text={notice} close={() => setNotice(null)} />
        <section className="view-wrap">
          {view === "devices" && (
            <Devices
              orgId={me.orgId}
              permissions={me.permissions}
              notify={setNotice}
            />
          )}
          {view === "people" && (
            <People
              orgId={me.orgId}
              permissions={me.permissions}
              roles={me.roles}
              user={me.user}
              notify={setNotice}
            />
          )}
          {view === "grants" && (
            <Grants
              orgId={me.orgId}
              permissions={me.permissions}
              notify={setNotice}
            />
          )}
          {view === "sessions" && (
            <Sessions
              orgId={me.orgId}
              permissions={me.permissions}
              user={me.user}
              notify={setNotice}
            />
          )}
          {view === "audit" && <Audit orgId={me.orgId} notify={setNotice} />}
          {view === "admin" && (
            <Admin
              orgId={me.orgId}
              org={org}
              permissions={me.permissions}
              notify={setNotice}
            />
          )}
        </section>
      </main>
    </div>
  );
}

function Devices({ orgId, permissions, notify }) {
  const [devices, setDevices] = useState(null);
  const [adding, setAdding] = useState(false);
  const load = () =>
    api(`/v1/orgs/${orgId}/devices`)
      .then((r) => setDevices(r.devices))
      .catch((e) => notify(errorText(e)));
  useEffect(() => {
    load();
  }, [orgId]);
  async function start(device, mode) {
    if (!mode) {
      notify(`File transfer is available for ${device.name}.`);
      return;
    }
    try {
      await api(`/v1/orgs/${orgId}/sessions`, {
        method: "POST",
        body: { deviceId: device.id, mode },
      });
      notify(`${mode} session started for ${device.name}.`);
    } catch (e) {
      notify(errorText(e));
    }
  }
  if (!devices) return <Skeleton />;
  return (
    <>
      <section className="section-intro">
        <p>
          Live device inventory. Actions appear only when the current server
          authority permits them.
        </p>
        {can(permissions, "device:provision") && (
          <Gate
            permission="device:provision"
            testId="add-device"
            className="primary"
            onClick={() => setAdding(true)}
          >
            <Plus size={17} />
            Add device
          </Gate>
        )}
      </section>
      {devices.length === 0 ? (
        <Empty
          testId="devices-empty"
          title="No devices yet"
          text="Add the first managed device to this organization."
        />
      ) : (
        <div className="device-grid">
          {devices.map((device) => (
            <article
              key={device.id}
              data-testid="device-row"
              data-device-id={device.id}
              className="device-card"
            >
              <div className="device-top">
                <div className="device-icon">
                  <Laptop size={24} />
                </div>
                <span className={device.online ? "online" : "offline"}>
                  {device.online ? "Online" : "Offline"}
                </span>
              </div>
              <div className="device-title">
                <h2>{device.name}</h2>
                <span>{device.kind}</span>
              </div>
              <div className="device-actions">
                {deviceActions
                  .filter(([permission]) => can(device.permissions, permission))
                  .map(([permission, label, Icon, mode, testId]) => (
                    <Gate
                      key={permission}
                      permission={permission}
                      testId={testId}
                      onClick={() => start(device, mode)}
                    >
                      <Icon size={16} />
                      {label}
                    </Gate>
                  ))}
                {can(device.permissions, "device:update") && (
                  <Gate
                    permission="device:update"
                    testId="rename-device"
                    onClick={() => renameDevice(orgId, device, load, notify)}
                  >
                    Rename
                  </Gate>
                )}
                {can(device.permissions, "device:provision") && (
                  <Gate
                    permission="device:provision"
                    testId="decommission-device"
                    className="danger"
                    onClick={() => deleteDevice(orgId, device, load, notify)}
                  >
                    Decommission
                  </Gate>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
      {adding && (
        <DeviceModal
          orgId={orgId}
          close={() => setAdding(false)}
          done={() => {
            setAdding(false);
            load();
          }}
          notify={notify}
        />
      )}
    </>
  );
}
function DeviceModal({ orgId, close, done, notify }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState("macos");
  async function submit(e) {
    e.preventDefault();
    try {
      await api(`/v1/orgs/${orgId}/devices`, {
        method: "POST",
        body: { name, kind, online: true },
      });
      done();
    } catch (err) {
      notify(errorText(err));
    }
  }
  return (
    <Modal title="Add device" close={close}>
      <form className="stack-form" onSubmit={submit}>
        <label>
          Name
          <input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </label>
        <label>
          Platform
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            {["macos", "windows", "linux", "android", "ios"].map((item) => (
              <option key={item}>{item}</option>
            ))}
          </select>
        </label>
        <button className="primary wide">Add device</button>
      </form>
    </Modal>
  );
}
async function renameDevice(orgId, device, load, notify) {
  const name = window.prompt("New device name", device.name);
  if (!name?.trim()) return;
  try {
    await api(`/v1/orgs/${orgId}/devices/${device.id}`, {
      method: "PATCH",
      body: { name: name.trim() },
    });
    load();
  } catch (e) {
    notify(errorText(e));
  }
}
async function deleteDevice(orgId, device, load, notify) {
  if (!window.confirm(`Decommission ${device.name}?`)) return;
  try {
    await api(`/v1/orgs/${orgId}/devices/${device.id}`, { method: "DELETE" });
    load();
  } catch (e) {
    notify(errorText(e));
  }
}

function People({ orgId, permissions, roles, user, notify }) {
  const [members, setMembers] = useState(null);
  const [invite, setInvite] = useState(false);
  const load = () =>
    api(`/v1/orgs/${orgId}/members`)
      .then((r) => setMembers(r.members))
      .catch((e) => notify(errorText(e)));
  useEffect(() => {
    load();
  }, [orgId]);
  if (!members) return <Skeleton />;
  return (
    <>
      <section className="section-intro">
        <p>
          People are scoped to this organization. Membership updates affect
          future authority immediately.
        </p>
        {can(permissions, "user:invite") && (
          <Gate
            permission="user:invite"
            testId="invite-user"
            className="primary"
            onClick={() => setInvite(true)}
          >
            <Plus size={17} />
            Invite person
          </Gate>
        )}
      </section>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Person</th>
              <th>Role</th>
              <th>Status</th>
              <th>
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {members.map((member) => (
              <tr
                key={member.id}
                data-testid="user-row"
                data-user-id={member.id}
              >
                <td>
                  <strong>{member.name}</strong>
                  <small>{member.email}</small>
                </td>
                <td>
                  {can(permissions, "user:role:update") &&
                  member.id !== user.id ? (
                    <select
                      aria-label={`Role for ${member.name}`}
                      data-testid="role-select"
                      value={member.role}
                      onChange={(e) =>
                        roleChange(
                          orgId,
                          member.id,
                          e.target.value,
                          load,
                          notify,
                        )
                      }
                    >
                      {roles.map((role) => (
                        <option key={role.key} value={role.key}>
                          {role.label}
                        </option>
                      ))}
                    </select>
                  ) : (
                    <span className="role-chip">{member.role}</span>
                  )}
                </td>
                <td>
                  <span className={`status ${member.status}`}>
                    {member.status}
                  </span>
                </td>
                <td className="row-actions">
                  {can(permissions, "user:remove") && member.id !== user.id && (
                    <>
                      <Gate
                        permission="user:remove"
                        testId="suspend-user"
                        onClick={() => suspend(orgId, member, load, notify)}
                      >
                        {member.status === "suspended"
                          ? "Reinstate"
                          : "Suspend"}
                      </Gate>
                      <Gate
                        permission="user:remove"
                        testId="remove-user"
                        className="danger"
                        onClick={() => remove(orgId, member, load, notify)}
                      >
                        Remove
                      </Gate>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {invite && (
        <InviteModal
          orgId={orgId}
          roles={roles}
          close={() => setInvite(false)}
          notify={notify}
        />
      )}
    </>
  );
}
async function roleChange(orgId, id, role, load, notify) {
  try {
    await api(`/v1/orgs/${orgId}/members/${id}`, {
      method: "PATCH",
      body: { role },
    });
    load();
  } catch (e) {
    notify(errorText(e));
    load();
  }
}
async function suspend(orgId, member, load, notify) {
  try {
    await api(`/v1/orgs/${orgId}/members/${member.id}/suspend`, {
      method: member.status === "suspended" ? "DELETE" : "POST",
      body: {},
    });
    load();
  } catch (e) {
    notify(errorText(e));
  }
}
async function remove(orgId, member, load, notify) {
  if (!window.confirm(`Remove ${member.name}?`)) return;
  try {
    await api(`/v1/orgs/${orgId}/members/${member.id}`, { method: "DELETE" });
    load();
  } catch (e) {
    notify(errorText(e));
  }
}
function InviteModal({ orgId, roles, close, notify }) {
  const defaultRole =
    roles.find((item) => item.key === "viewer")?.key || roles.at(-1)?.key || "";
  const [email, setEmail] = useState("");
  const [role, setRole] = useState(defaultRole);
  const [created, setCreated] = useState(null);
  async function submit(e) {
    e.preventDefault();
    try {
      setCreated(
        await api(`/v1/orgs/${orgId}/invites`, {
          method: "POST",
          body: { email, role },
        }),
      );
    } catch (err) {
      notify(errorText(err));
    }
  }
  return (
    <Modal title="Invite person" close={close}>
      {created ? (
        <div className="invite-result">
          <p>Invitation created. This link is shown once.</p>
          <code>
            {location.origin}/invite/{created.inviteToken}
          </code>
        </div>
      ) : (
        <form className="stack-form" onSubmit={submit}>
          <label>
            Email
            <input
              name="invite-email"
              type="email"
              autoComplete="off"
              spellCheck={false}
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </label>
          <label>
            Role
            <select
              name="invite-role"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              {roles.map((item) => (
                <option key={item.key} value={item.key}>
                  {item.label}
                </option>
              ))}
            </select>
          </label>
          <button className="primary wide">Create invitation</button>
        </form>
      )}
    </Modal>
  );
}

function Grants({ orgId, permissions, notify }) {
  const [data, setData] = useState(null);
  const [form, setForm] = useState(false);
  const load = () =>
    Promise.all([
      api(`/v1/orgs/${orgId}/grants`),
      api(`/v1/orgs/${orgId}/members`),
      api(`/v1/orgs/${orgId}/devices`),
    ])
      .then(([grants, members, devices]) =>
        setData({
          grants: grants.grants,
          members: members.members,
          devices: devices.devices,
        }),
      )
      .catch((e) => notify(errorText(e)));
  useEffect(() => {
    setData(null);
    load();
  }, [orgId]);
  if (!data) return <Skeleton />;
  const { grants, members, devices } = data;
  const keys = [
    ...new Set(
      Object.keys(permissions || {}).concat(
        devices.flatMap((d) => Object.keys(d.permissions || {})),
      ),
    ),
  ].sort();
  return (
    <>
      <section className="section-intro">
        <p>Explicit exceptions layered on top of role baselines.</p>
        {can(permissions, "grant:create") && (
          <Gate
            permission="grant:create"
            testId="new-grant"
            className="primary"
            onClick={() => setForm(true)}
          >
            <Plus size={17} />
            New grant
          </Gate>
        )}
      </section>
      <div className="grant-list">
        {grants.map((grant) => (
          <article
            key={grant.id}
            data-testid="grant-row"
            data-effect={grant.effect}
            className={`grant-item ${grant.effect}`}
          >
            <span className="grant-effect">
              {grant.effect === "allow" ? (
                <CheckCircle size={18} />
              ) : (
                <X size={18} />
              )}
            </span>
            <div>
              <strong>
                {members.find((m) => m.id === grant.user_id)?.name ||
                  grant.user_id}
              </strong>
              <p>
                {grant.permissions.join(", ")}
                {grant.device_id
                  ? ` on ${devices.find((d) => d.id === grant.device_id)?.name || grant.device_id}`
                  : " across organization"}
              </p>
            </div>
            <small>
              {grant.expires_at
                ? `Ends ${friendlyDate(grant.expires_at)}`
                : "No expiry"}
            </small>
            {can(permissions, "grant:revoke") && (
              <Gate
                permission="grant:revoke"
                testId="revoke-grant"
                className="danger"
                onClick={() => revoke(orgId, grant.id, load, notify)}
              >
                Revoke
              </Gate>
            )}
          </article>
        ))}
      </div>
      {form && (
        <GrantModal
          orgId={orgId}
          members={members}
          devices={devices}
          keys={keys}
          close={() => setForm(false)}
          done={() => {
            setForm(false);
            load();
          }}
          notify={notify}
        />
      )}
    </>
  );
}
async function revoke(orgId, id, load, notify) {
  try {
    await api(`/v1/orgs/${orgId}/grants/${id}`, { method: "DELETE" });
    load();
  } catch (e) {
    notify(errorText(e));
  }
}
function GrantModal({ orgId, members, devices, keys, close, done, notify }) {
  const [userId, setUserId] = useState(members[0]?.id || "");
  const [deviceId, setDeviceId] = useState("");
  const [effect, setEffect] = useState("allow");
  const [selected, setSelected] = useState([]);
  async function submit(e) {
    e.preventDefault();
    try {
      await api(`/v1/orgs/${orgId}/grants`, {
        method: "POST",
        body: {
          userId,
          deviceId: deviceId || null,
          effect,
          permissions: selected,
        },
      });
      done();
    } catch (err) {
      notify(errorText(err));
    }
  }
  return (
    <Modal title="Create access grant" close={close}>
      <form className="stack-form" onSubmit={submit}>
        <label>
          Member
          <select
            data-testid="grant-user"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          >
            {members.map((m) => (
              <option key={m.id} value={m.id}>
                {m.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Scope
          <select
            data-testid="grant-device"
            value={deviceId}
            onChange={(e) => setDeviceId(e.target.value)}
          >
            <option value="">Organization wide</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          Effect
          <select
            data-testid="grant-effect"
            value={effect}
            onChange={(e) => setEffect(e.target.value)}
          >
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </label>
        <fieldset>
          <legend>Permissions</legend>
          <div className="checkbox-grid">
            {keys.map((key) => (
              <label key={key} className="checkbox">
                <input
                  data-permission-key={key}
                  type="checkbox"
                  checked={selected.includes(key)}
                  onChange={(e) =>
                    setSelected((all) =>
                      e.target.checked
                        ? [...all, key]
                        : all.filter((item) => item !== key),
                    )
                  }
                />
                {key}
              </label>
            ))}
          </div>
        </fieldset>
        <button data-testid="grant-submit" className="primary wide">
          Create grant
        </button>
      </form>
    </Modal>
  );
}

function Sessions({ orgId, permissions, user, notify }) {
  const [sessions, setSessions] = useState(null);
  const load = () =>
    api(`/v1/orgs/${orgId}/sessions`)
      .then((r) => setSessions(r.sessions))
      .catch((e) => notify(errorText(e)));
  useEffect(() => {
    load();
  }, [orgId]);
  if (!sessions) return <Skeleton />;
  return (
    <>
      <section className="section-intro">
        <p>Connections retain their authorization snapshot until they end.</p>
        {can(permissions, "session:start") && (
          <span
            data-testid="new-session"
            data-permission="session:start"
            data-state="unlocked"
            className="meta-access"
          >
            Start a session from a device
          </span>
        )}
      </section>
      {sessions.length === 0 ? (
        <Empty
          title="No sessions"
          text="Connections will appear here as they start."
        />
      ) : (
        <div className="session-list">
          {sessions.map((session) => (
            <article
              key={session.id}
              data-testid="session-row"
              className="session-item"
            >
              <span className="session-mode">
                {session.mode === "terminal" ? (
                  <Terminal size={18} />
                ) : (
                  <Desktop size={18} />
                )}
              </span>
              <div>
                <strong>{session.mode} session</strong>
                <p>
                  {session.device_id} · started{" "}
                  {friendlyDate(session.started_at)}
                </p>
              </div>
              <span className={`status ${session.state}`}>{session.state}</span>
              {(session.user_id === user.id ||
                can(permissions, "session:terminate")) &&
                ["active", "connecting"].includes(session.state) && (
                  <Gate
                    permission={
                      session.user_id === user.id
                        ? "session:own"
                        : "session:terminate"
                    }
                    testId="stop-session"
                    className="danger"
                    onClick={() => stop(session.id, load, notify)}
                  >
                    Stop
                  </Gate>
                )}
            </article>
          ))}
        </div>
      )}
    </>
  );
}
async function stop(id, load, notify) {
  try {
    await api(`/v1/sessions/${id}`, { method: "DELETE" });
    load();
  } catch (e) {
    notify(errorText(e));
  }
}
function Audit({ orgId, notify }) {
  const [events, setEvents] = useState(null);
  useEffect(() => {
    api(`/v1/orgs/${orgId}/audit?limit=50`)
      .then((r) => setEvents(r.events))
      .catch((e) => notify(errorText(e)));
  }, [orgId]);
  if (!events) return <Skeleton count={5} />;
  return (
    <div className="audit-list">
      {events.map((event) => (
        <article key={event.id} data-testid="audit-row" className="audit-item">
          <span
            className={event.result === "allow" ? "audit-allow" : "audit-deny"}
          >
            {event.result === "allow" ? (
              <CheckCircle size={16} />
            ) : (
              <X size={16} />
            )}
          </span>
          <div>
            <strong>{event.action}</strong>
            <p>
              {event.target_type} {event.target_id}
            </p>
          </div>
          <time>{friendlyDate(event.at)}</time>
        </article>
      ))}
    </div>
  );
}
function Admin({ orgId, org, permissions, notify }) {
  const [name, setName] = useState(org?.name || "");
  useEffect(() => setName(org?.name || ""), [org]);
  async function rename() {
    try {
      await api(`/v1/orgs/${orgId}`, { method: "PATCH", body: { name } });
      notify("Organization name updated.");
    } catch (e) {
      notify(errorText(e));
    }
  }
  async function removeOrg() {
    if (!window.confirm(`Delete ${org?.name}?`)) return;
    try {
      await api(`/v1/orgs/${orgId}`, { method: "DELETE" });
      notify("Organization deleted.");
    } catch (e) {
      notify(errorText(e));
    }
  }
  return (
    <div className="admin-layout">
      <section className="admin-block">
        <p className="eyebrow">Organization settings</p>
        <h2>Identity</h2>
        <label>
          Organization name
          <input value={name} onChange={(e) => setName(e.target.value)} />
        </label>
        {can(permissions, "org:update") && (
          <Gate
            permission="org:update"
            testId="rename-org"
            className="primary"
            onClick={rename}
          >
            Save name
          </Gate>
        )}
      </section>
      {can(permissions, "org:delete") && (
        <section className="admin-block danger-zone">
          <p className="eyebrow">Permanent action</p>
          <h2>Delete organization</h2>
          <p>
            Devices, people, and active sessions will no longer be accessible.
          </p>
          <Gate
            permission="org:delete"
            testId="delete-org"
            className="danger"
            onClick={removeOrg}
          >
            Delete organization
          </Gate>
        </section>
      )}
    </div>
  );
}

createRoot(document.getElementById("root")).render(<App />);
