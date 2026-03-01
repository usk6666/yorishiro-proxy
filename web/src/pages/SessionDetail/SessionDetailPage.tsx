import { useParams } from "react-router-dom";
import "./SessionDetailPage.css";

export function SessionDetailPage() {
  const { id } = useParams<{ id: string }>();

  return (
    <div className="page session-detail-page">
      <h1 className="page-title">Session Detail</h1>
      <p className="page-description">
        Session ID: <code>{id}</code>
      </p>
      <div className="page-placeholder">
        Request/response details will be displayed here.
      </div>
    </div>
  );
}
