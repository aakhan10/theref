import { createContext, useContext, useEffect, useState } from "react";
import { apiFetch } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [accessToken, setAccessToken] = useState(null);
  const [loading, setLoading] = useState(true);

  async function signup(email, password) {
    const data = await apiFetch("/auth/register", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    return data;
  }

  async function login(email, password) {
    const data = await apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });

    setAccessToken(data.accessToken);
    setUser(data.user);
    return data;
  }

  async function logout() {
    try {
      await apiFetch("/auth/logout", {
        method: "POST",
      });
    } catch (err) {
      console.error("Logout error:", err);
    } finally {
      setAccessToken(null);
      setUser(null);
    }
  }

  async function refreshAccessToken() {
    const data = await apiFetch("/auth/refresh", {
      method: "POST",
    });

    setAccessToken(data.accessToken);
    return data.accessToken;
  }

  async function fetchMe(token) {
    const data = await apiFetch("/auth/me", {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    setUser(data.user);
    return data.user;
  }

  useEffect(() => {
    async function initAuth() {
      try {
        const newToken = await refreshAccessToken();
        await fetchMe(newToken);
      } catch (err) {
        setAccessToken(null);
        setUser(null);
      } finally {
        setLoading(false);
      }
    }

    initAuth();
  }, []);

  return (
    <AuthContext.Provider
      value={{
        user,
        accessToken,
        loading,
        signup,
        login,
        logout,
        refreshAccessToken,
        fetchMe,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return ctx;
}