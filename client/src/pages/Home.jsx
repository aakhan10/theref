import { useAuth } from "../context/AuthContext";

export default function Home() {
  const { user, logout } = useAuth();

  return (
    <div style={{ padding: "2rem" }}>
      <h1>The Ref</h1>
      <p>Welcome, {user?.email}</p>
      <p>Role: {user?.role}</p>

      <button onClick={logout}>Logout</button>
    </div>
  );
}