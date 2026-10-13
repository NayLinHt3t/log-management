import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import "@fontsource-variable/atkinson-hyperlegible-next";
import "@fontsource-variable/atkinson-hyperlegible-mono";
import "./styles.css";
import { AuthProvider, useAuth } from "./auth";
import { Layout } from "./components/Layout";
import { ToastProvider } from "./components/ui";
import { Admin } from "./pages/Admin";
import { Alerts } from "./pages/Alerts";
import { Dashboard } from "./pages/Dashboard";
import { Login } from "./pages/Login";
import { Search } from "./pages/Search";
import { Sources } from "./pages/Sources";

// apply the stored theme before first paint
try {
  const t = JSON.parse(localStorage.getItem("logmgmt.theme") ?? '"system"');
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch {
  /* storage unavailable */
}

function App() {
  const { user, ready } = useAuth();
  if (!ready) return null;
  if (!user) return <Login />;
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route index element={<Dashboard />} />
        <Route path="search" element={<Search />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="sources" element={<Sources />} />
        <Route path="admin" element={user.role === "admin" ? <Admin /> : <Navigate to="/" replace />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <App />
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  </StrictMode>,
);
