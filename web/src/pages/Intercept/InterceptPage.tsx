import "./InterceptPage.css";

export function InterceptPage() {
  return (
    <div className="page intercept-page">
      <h1 className="page-title">Intercept</h1>
      <p className="page-description">
        Intercepted requests waiting for review.
      </p>
      <div className="page-placeholder">
        Intercept queue will be displayed here.
      </div>
    </div>
  );
}
