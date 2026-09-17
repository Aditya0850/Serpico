import { useState } from 'react';
import axios from 'axios';

function App() {
  const [evidenceType, setEvidenceType] = useState('text');
  const [evidenceContent, setEvidenceContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const response = await axios.post('http://localhost:8001/investigate', {
        type: evidenceType,
        content: evidenceContent,
      });
      setResult(response.data);
    } catch (err) {
      setError('Failed to submit investigation. Please try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="App">
      <header className="app-header">
        <h1>TRACE</h1>
        <p>Don't just detect. Investigate.</p>
      </header>

      <main>
        <section className="investigation-form">
          <h2>Submit Evidence</h2>
          <form onSubmit={handleSubmit}>
            <div>
              <label>
                Evidence Type:
                <select
                  value={evidenceType}
                  onChange={(e) => setEvidenceType(e.target.value)}
                >
                  <option value="text">Text</option>
                  <option value="image">Image (base64)</option>
                  <option value="url">URL</option>
                </select>
              </label>
            </div>
            <div>
              <label>
                Evidence Content:
                <textarea
                  value={evidenceContent}
                  onChange={(e) => setEvidenceContent(e.target.value)}
                  placeholder="Enter text, base64 image, or URL..."
                  rows={4}
                />
              </label>
            </div>
            <button type="submit" disabled={loading}>
              {loading ? 'Investigating...' : 'Start Investigation'}
            </button>
          </form>
          {error && <p className="error">{error}</p>}
        </section>

        {result && (
          <section className="investigation-result">
            <h2>Investigation Results</h2>
            <div className="result-case-id">
              <strong>Case ID:</strong> {result.case_id}
            </div>
            <div className="result-verdict">
              <strong>Risk Level:</strong> {result.verdict.risk_level}
              <br />
              <strong>Confidence:</strong> {(result.verdict.confidence * 100).toFixed(1)}%
            </div>
            <div className="result-reasoning">
              <strong>Reasoning:</strong>
              <ul>
                {result.verdict.reasoning.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </div>
            <div className="result-actions">
              <strong>Recommended Actions:</strong>
              <ul>
                {result.verdict.recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
            <div className="result-timestamp">
              <em>Investigated at: {new Date(result.timestamp).toLocaleString()}</em>
            </div>
          </section>
        )}
      </main>

      <footer className="app-footer">
        <p>TRACE - Multi-Agent AI Cybersecurity Investigation System</p>
      </footer>
    </div>
  );
}

export default App;