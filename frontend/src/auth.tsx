import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, setMemoryToken, tokenStore, type User } from "./api";

interface AuthState {
  user: User | null;
  ready: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(false);

  const logout = useCallback(() => {
    tokenStore.set(null);
    setMemoryToken(null);
    setUser(null);
  }, []);

  useEffect(() => {
    const token = tokenStore.get();
    if (!token) {
      setReady(true);
      return;
    }
    api<User>("/auth/me")
      .then(setUser)
      .catch(() => logout())
      .finally(() => setReady(true));
  }, [logout]);

  useEffect(() => {
    const onExpired = () => logout();
    window.addEventListener("auth:expired", onExpired);
    return () => window.removeEventListener("auth:expired", onExpired);
  }, [logout]);

  const login = useCallback(async (username: string, password: string) => {
    const res = await api<{ token: string; user: User }>("/auth/login", {
      body: { username, password },
    });
    tokenStore.set(res.token);
    setMemoryToken(res.token);
    setUser(res.user);
  }, []);

  const value = useMemo(() => ({ user, ready, login, logout }), [user, ready, login, logout]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth outside AuthProvider");
  return ctx;
}

// eslint-disable-next-line react-refresh/only-export-components
export function useUser(): User {
  const { user } = useAuth();
  if (!user) throw new Error("not logged in");
  return user;
}
