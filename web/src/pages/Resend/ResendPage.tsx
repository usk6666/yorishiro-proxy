import { useParams } from "react-router-dom";
import "./ResendPage.css";

export function ResendPage() {
  const { sessionId } = useParams<{ sessionId: string }>();

  return (
    <div className="page resend-page">
      <h1 className="page-title">Resend</h1>
      <p className="page-description">
        {sessionId
          ? <>Resend session: <code>{sessionId}</code></>
          : "Compose and resend HTTP requests."}
      </p>
      <div className="page-placeholder">
        Request editor will be displayed here.
      </div>
    </div>
  );
}
