import ScoreMeter from "./ScoreMeter";


function RiskCard({ result }) {
  const {
    input_url,
    risk_score,
    risk_level,
    threat_type,
    summary,
    signals,
    risk_breakdown,
    recommended_actions,
    disclaimer,
  } = result;

  return (
    <section className="risk-card">
      <div className="risk-card-header">
        <ScoreMeter
          score={risk_score}
          riskLevel={risk_level}
        />

        <div className="threat-details">
          <p className="small-label">
            Threat Classification
          </p>

          <h2>{threat_type}</h2>

          <p>{summary}</p>
        </div>
      </div>

      <div className="analyzed-url">
        <span>Analyzed URL</span>
        <p>{input_url}</p>
      </div>

      <div className="result-section">
        <h3>Technical Signals</h3>

        <div className="signal-grid">
          <SignalItem
            label="HTTPS missing"
            detected={!signals.uses_https}
          />

          <SignalItem
            label="IP address used"
            detected={signals.contains_ip_address}
          />

          <SignalItem
            label="@ symbol detected"
            detected={signals.contains_at_symbol}
          />

          <SignalItem
            label="Punycode detected"
            detected={signals.contains_punycode}
          />

          <SignalItem
            label="Long URL"
            detected={signals.is_long_url}
          />

          <SignalItem
            label="Many subdomains"
            detected={signals.has_many_subdomains}
          />
        </div>

        {signals.suspicious_keywords?.length > 0 && (
          <div className="extra-signal">
            <strong>Suspicious keywords:</strong>{" "}
            {signals.suspicious_keywords.join(", ")}
          </div>
        )}

        {signals.possible_brand_impersonation?.length >
          0 && (
          <div className="extra-signal">
            <strong>
              Possible brand impersonation:
            </strong>{" "}
            {signals.possible_brand_impersonation.join(
              ", "
            )}
          </div>
        )}
      </div>

      <div className="result-section">
        <h3>Why this score?</h3>

        {risk_breakdown?.length > 0 ? (
          <div className="breakdown-list">
            {risk_breakdown.map((item, index) => (
              <div
                className="breakdown-item"
                key={`${item.signal}-${index}`}
              >
                <div>
                  <strong>{item.signal}</strong>
                  <p>{item.reason}</p>
                </div>

                <span>+{item.points}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="muted-text">
            No scored warning signals detected.
          </p>
        )}
      </div>

      <div className="result-section">
        <h3>Recommended Actions</h3>

        <ul>
          {recommended_actions?.map(
            (action, index) => (
              <li key={index}>{action}</li>
            )
          )}
        </ul>
      </div>

      {disclaimer && (
        <p className="disclaimer">{disclaimer}</p>
      )}
    </section>
  );
}


function SignalItem({ label, detected }) {
  return (
    <div
      className={
        detected
          ? "signal-item signal-warning"
          : "signal-item signal-safe"
      }
    >
      <span>{detected ? "⚠" : "✓"}</span>
      {label}
    </div>
  );
}


export default RiskCard;