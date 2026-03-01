import { useParams } from "react-router-dom";
import "./FuzzResultsPage.css";

export function FuzzResultsPage() {
  const { fuzzId } = useParams<{ fuzzId: string }>();

  return (
    <div className="page fuzz-results-page">
      <h1 className="page-title">Fuzz Results</h1>
      <p className="page-description">
        Fuzz job ID: <code>{fuzzId}</code>
      </p>
      <div className="page-placeholder">
        Fuzz results will be displayed here.
      </div>
    </div>
  );
}
