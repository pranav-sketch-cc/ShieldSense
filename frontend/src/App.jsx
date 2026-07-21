import { useState } from "react";
import RiskCard from "./components/RiskCard";

import {
  analyzeURL,
  checkBackendHealth,
} from "./services/api";


function App() {
  const [backendStatus, setBackendStatus] =
    useState("Not checked");

  const [url, setURL] = useState("");

  const [analysisResult, setAnalysisResult] =
    useState(null);

  const [error, setError] = useState("");

  const [isLoading, setIsLoading] =
    useState(false);


  async function handleHealthCheck() {
    setBackendStatus("Checking...");

    try {
      const response = await checkBackendHealth();

      setBackendStatus(
        response.status || "Backend is running"
      );
    } catch (requestError) {
      setBackendStatus(requestError.message);
    }
  }


  async function handleAnalyze(event) {
    event.preventDefault();

    const cleanedURL = url.trim();

    if (!cleanedURL) {
      setError("Please enter a URL.");
      setAnalysisResult(null);
      return;
    }

    setIsLoading(true);
    setError("");
    setAnalysisResult(null);

    try {
      const result = await analyzeURL(cleanedURL);

      setAnalysisResult(result);
    } catch (requestError) {
      setError(requestError.message);
    } finally {
      setIsLoading(false);
    }
  }


  return (
    <main>
      <h1>ShieldSense</h1>

      <section>
        <p>
          Backend status: {backendStatus}
        </p>

        <button
          type="button"
          onClick={handleHealthCheck}
        >
          Check Backend
        </button>
      </section>

      <form onSubmit={handleAnalyze}>
        <label htmlFor="url-input">
          Enter a URL
        </label>

        <input
          id="url-input"
          type="text"
          value={url}
          onChange={(event) =>
            setURL(event.target.value)
          }
          placeholder="https://example.com"
        />

        <button
          type="submit"
          disabled={isLoading}
        >
          {isLoading
            ? "Analyzing..."
            : "Analyze URL"}
        </button>
      </form>

      {error && (
        <p className="error-message">
          {error}
        </p>
      )}

      {analysisResult && (
  <RiskCard result={analysisResult} />
)}

    </main>
  );
}

export default App;