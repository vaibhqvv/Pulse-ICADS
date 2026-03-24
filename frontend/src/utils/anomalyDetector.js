const DEFAULT_ANOMALY_THRESHOLD = 0.5;
const DEFAULT_ATTACK_THRESHOLD = 0.75;
export function classifyScore(score, anomalyThreshold, attackThreshold) {
  const at = anomalyThreshold ?? DEFAULT_ANOMALY_THRESHOLD;
  const ct = attackThreshold ?? DEFAULT_ATTACK_THRESHOLD;

  if (score >= ct) return 'attack';
  if (score >= at) return 'suspicious';
  return 'normal';
}
export function getScoreColor(score) {
  if (score >= 0.75) return '#B44B4B';   // Dusty rose
  if (score >= 0.5) return '#B8963E';    // Ochre
  if (score >= 0.25) return '#C67A3C';   // Burnt orange
  return '#5B8A52';                       // Sage green
}
export function getRiskLevel(score) {
  if (score >= 0.9) return 'Critical Risk';
  if (score >= 0.75) return 'High Risk';
  if (score >= 0.5) return 'Elevated Risk';
  if (score >= 0.25) return 'Low Risk';
  return 'Minimal Risk';
}
export function scoreToPercentage(score) {
  return Math.round(Math.max(0, Math.min(1, score)) * 100);
}
