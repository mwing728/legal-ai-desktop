import { lazy, Suspense, useState, useCallback } from "react";
import { Routes, Route, NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Briefcase,
  FileText,
  Users,
  MessageSquare,
  Inbox,
  Settings,
  Scale,
  Shield,
  Loader2,
} from "lucide-react";
import Setup from "./pages/Setup";

const Dashboard = lazy(() => import("./pages/Dashboard"));
const Matters = lazy(() => import("./pages/Matters"));
const Documents = lazy(() => import("./pages/Documents"));
const Clients = lazy(() => import("./pages/Clients"));
const Chat = lazy(() => import("./pages/Chat"));
const InboxPage = lazy(() => import("./pages/InboxPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));

const navItems = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/matters", icon: Briefcase, label: "Matters" },
  { to: "/documents", icon: FileText, label: "Documents" },
  { to: "/clients", icon: Users, label: "Clients" },
  { to: "/chat", icon: MessageSquare, label: "AI Chat" },
  { to: "/inbox", icon: Inbox, label: "Inbox" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

function PageLoader() {
  return (
    <div className="flex items-center justify-center h-full">
      <div className="flex items-center gap-3 text-zinc-500">
        <Loader2 className="w-5 h-5 animate-spin" />
        <span className="text-sm">Loading...</span>
      </div>
    </div>
  );
}

export default function App() {
  const [ollamaReady, setOllamaReady] = useState(false);
  const handleReady = useCallback(() => setOllamaReady(true), []);

  if (!ollamaReady) {
    return <Setup onReady={handleReady} />;
  }

  return (
    <div className="flex h-screen bg-zinc-950 text-zinc-100 overflow-hidden">
      {/* Sidebar */}
      <aside className="w-60 border-r border-zinc-800 flex flex-col bg-zinc-950/80 backdrop-blur-sm">
        <div className="p-5 border-b border-zinc-800">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-amber-600 flex items-center justify-center">
              <Scale className="w-4.5 h-4.5 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight">Legal AI</h1>
              <p className="text-[10px] text-zinc-500 flex items-center gap-1">
                <Shield className="w-2.5 h-2.5" /> IronClaw Secured
              </p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-3 space-y-0.5">
          {navItems.map(({ to, icon: Icon, label }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/"}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors ${
                  isActive
                    ? "bg-amber-600/15 text-amber-400 font-medium"
                    : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50"
                }`
              }
            >
              <Icon className="w-4 h-4" />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-zinc-800">
          <div className="text-[10px] text-zinc-600 text-center">
            Powered by Ollama &middot; phi4-mini
          </div>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 overflow-y-auto">
        <Suspense fallback={<PageLoader />}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/matters" element={<Matters />} />
            <Route path="/documents" element={<Documents />} />
            <Route path="/clients" element={<Clients />} />
            <Route path="/chat" element={<Chat />} />
            <Route path="/inbox" element={<InboxPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  );
}
