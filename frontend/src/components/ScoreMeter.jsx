function ScoreMeter({ score, riskLevel }) {
  const safeScore = Math.min(
    Math.max(Number(score) || 0, 0),
    100
  );

  const riskClass = String(riskLevel)
    .toLowerCase()
    .replaceAll(" ", "-");

  return (
    <div className="score-meter">
      <div
        className={`score-circle risk-${riskClass}`}
        style={{
          "--score-angle": `${safeScore * 3.6}deg`,
        }}
      >
        <div className="score-circle-inner">
          <strong>{safeScore}</strong>
          <span>/ 100</span>
        </div>
      </div>

      <div className="score-text">
        <p>Risk Score</p>
        <h2>{riskLevel} Risk</h2>
      </div>
    </div>
  );
}

export default ScoreMeter;