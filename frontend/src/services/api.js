const API_BASE_URL = "http://127.0.0.1:8000";


export async function checkBackendHealth() {
  const response = await fetch(`${API_BASE_URL}/health`);

  if (!response.ok) {
    throw new Error("Backend health check failed.");
  }

  return response.json();
}


export async function analyzeURL(url) {
  const response = await fetch(
    `${API_BASE_URL}/api/analyze/url`,
    {
      method: "POST",

      headers: {
        "Content-Type": "application/json",
      },

      body: JSON.stringify({
        url: url,
      }),
    }
  );

  const data = await response.json();

  if (!response.ok) {
    const errorMessage =
      typeof data.detail === "string"
        ? data.detail
        : "URL analysis failed.";

    throw new Error(errorMessage);
  }

  return data;
}