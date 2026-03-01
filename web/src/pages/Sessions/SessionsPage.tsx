import "./SessionsPage.css";

export function SessionsPage() {
  return (
    <div className="page sessions-page">
      <h1 className="page-title">Sessions</h1>
      <p className="page-description">
        Captured HTTP/HTTPS, WebSocket, gRPC, and TCP sessions.
      </p>
      <div className="page-placeholder">
        Session list will be displayed here.
      </div>
    </div>
  );
}
