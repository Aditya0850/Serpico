import { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import './App.css';

function FindingList({ items, visibleCount = items?.length || 0, emptyLabel = 'No findings returned.' }) {
  if (!items?.length) {
    return <p className="stage-empty">{emptyLabel}</p>;
  }

  return (
    <ul className="stage-findings">
      {items.slice(0, visibleCount).map((item, index) => {
        const finding = typeof item === 'string' ? item : item.description;
        const evidence = typeof item === 'string' ? null : item.evidence;

        return (
          <li key={`${finding}-${index}`}>
            <span className="finding-bullet" aria-hidden="true" />
            <span>
              <span className="finding-text">{finding}</span>
              {evidence && <small>{evidence}</small>}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function EvidenceOutput({ result, visibleCount }) {
  const extracted = result.extracted_evidence || {};
  const references = [...(extracted.urls || []), ...(extracted.entities || []), ...(extracted.indicators || [])];
  const items = [
    ...references.map((reference) => `Reference: ${reference}`),
    ...(result.agents?.evidence?.findings || []),
  ];

  return (
    <div className="stage-output">
      <p className="output-label">EXTRACTED EVIDENCE</p>
      <div className="evidence-summary"><span>{extracted.urls?.length || 0} URLs</span><span>{extracted.entities?.length || 0} entities</span><span>{extracted.indicators?.length || 0} indicators</span></div>
      <FindingList items={items} visibleCount={visibleCount} />
    </div>
  );
}

function ViewHeader({ label, onBack, onReturn }) {
  return (
    <header className="investigation-header">
      <button className="back-button" type="button" onClick={onBack}>
        <span aria-hidden="true">&lt;-</span> Back
      </button>
      <span className="investigation-header-label">TRACE / {label}</span>
      <button className="back-button" type="button" onClick={onReturn}>Return to intake</button>
    </header>
  );
}

function InvestigationPage({ result, onContinue, onBack, onReturn }) {
  const investigatorStages = [
    ['Evidence Investigator', 'Extracting entities, links and indicators', '01', 'E'],
    ['Social Engineering Investigator', 'Mapping pressure and manipulation signals', '02', 'S'],
    ['Threat Intelligence Investigator', 'Comparing domains against known indicators', '03', 'T'],
  ];
  const stageItems = useMemo(() => [
    [...(result.extracted_evidence?.urls || []), ...(result.extracted_evidence?.entities || []), ...(result.extracted_evidence?.indicators || []), ...(result.agents?.evidence?.findings || [])],
    [...(result.agents?.social_engineering?.findings || []), ...(result.agents?.social_engineering?.indicators || [])],
    [...(result.agents?.threat_intelligence?.findings || []), ...(result.agents?.threat_intelligence?.indicators || [])],
  ], [result]);
  const [activeStage, setActiveStage] = useState(0);
  const [visibleCount, setVisibleCount] = useState(0);
  const [stagePhase, setStagePhase] = useState('analyzing');
  const [completed, setCompleted] = useState(false);

  useEffect(() => {
    if (completed) return undefined;
    const total = stageItems[activeStage].length;
    if (stagePhase === 'complete') {
      const nextTimer = window.setTimeout(() => {
        if (activeStage < investigatorStages.length - 1) {
          setActiveStage((stage) => stage + 1);
          setVisibleCount(0);
          setStagePhase('analyzing');
        } else {
          setCompleted(true);
        }
      }, 700);
      return () => window.clearTimeout(nextTimer);
    }
    const timer = window.setTimeout(() => {
      if (visibleCount < total) setVisibleCount((count) => count + 1);
      else setStagePhase('complete');
    }, visibleCount < total ? 650 : 650);
    return () => window.clearTimeout(timer);
  }, [activeStage, completed, investigatorStages.length, stageItems, stagePhase, visibleCount]);

  useEffect(() => {
    if (!completed) return undefined;
    const timer = window.setTimeout(onContinue, 900);
    return () => window.clearTimeout(timer);
  }, [completed, onContinue]);

  const findingCount = (result.agents?.evidence?.findings?.length || 0)
    + (result.agents?.social_engineering?.findings?.length || 0)
    + (result.agents?.threat_intelligence?.findings?.length || 0);
  const indicators = result.extracted_evidence?.indicators || [];

  return (
    <div className="investigation-screen">
      <ViewHeader label="INVESTIGATION RECORD" onBack={onBack} onReturn={onReturn} />
      <main className="investigation-main">
        <section className="investigation-intro">
          <p className="eyebrow">CASE {result.case_id} / INVESTIGATION STAGE</p>
          <h1>Investigation</h1>
          <p className="investigation-intro-copy">TRACE has examined the evidence through three independent investigative lenses.</p>
          <div className="investigation-status-line"><span className="status-dot" aria-hidden="true" /><span>PRELIMINARY RECORD ASSEMBLED</span><span className="status-divider" aria-hidden="true" /><span>STAGES 03 / 03</span></div>
        </section>
        <section className="agent-pipeline investigation-sections" aria-label="Investigator findings">
          <div className="pipeline-heading"><span>INVESTIGATOR OUTPUT</span><span>STAGE {Math.min(activeStage + 1, investigatorStages.length)} / {investigatorStages.length}</span></div>
          <div className="pipeline-track">
            {investigatorStages.map(([name, description, marker, icon], index) => {
              const isComplete = completed || index < activeStage || (index === activeStage && stagePhase === 'complete');
              const isAnalyzing = !completed && index === activeStage && stagePhase === 'analyzing';
              const output = index === 0 ? <EvidenceOutput result={result} visibleCount={isComplete ? stageItems[index].length : visibleCount} /> : <div className="stage-output"><p className="output-label">{index === 1 ? 'SOCIAL SIGNALS' : 'THREAT INDICATORS'}</p><FindingList items={stageItems[index]} visibleCount={isComplete ? stageItems[index].length : visibleCount} /></div>;
              return (
              <article className={`agent-stage ${isComplete ? 'complete' : isAnalyzing ? 'analyzing' : 'waiting'}`} key={name}>
                <div className="stage-marker"><span>{icon}</span></div>
                <div className="stage-content"><div className="stage-meta"><span>REF / {marker}</span><strong>{isComplete ? 'COMPLETE' : isAnalyzing ? 'ANALYZING...' : 'WAITING'}</strong></div><h2>{name}</h2><p>{description}</p>{(isComplete || (isAnalyzing && visibleCount > 0)) && output}</div>
              </article>
              );
            })}
          </div>
        </section>
        {completed && <section className="preliminary-assessment"><div className="pipeline-heading"><span>PRELIMINARY ASSESSMENT</span><span>JUDGE NOT YET CONSULTED</span></div><p>The investigator record contains {findingCount} observed finding{findingCount === 1 ? '' : 's'}{indicators.length ? ` across ${indicators.length} extracted signal${indicators.length === 1 ? '' : 's'}` : ''}. The evidence is ready for adversarial review.</p></section>}
      </main>
    </div>
  );
}

function DevilsAdvocatePage({ result, onContinue, onBack, onReturn }) {
  const challenges = result.devils_advocate?.challenges || [];
  const counterEvidence = result.devils_advocate?.counter_evidence || [];
  const revealSequence = useMemo(() => {
    const pairedItems = [];
    const pairCount = Math.max(challenges.length, counterEvidence.length);

    for (let index = 0; index < pairCount; index += 1) {
      if (challenges[index]) pairedItems.push({ type: 'challenge', number: index + 1, item: challenges[index] });
      if (counterEvidence[index]) pairedItems.push({ type: 'counter', number: index + 1, item: counterEvidence[index] });
    }

    return pairedItems;
  }, [challenges, counterEvidence]);
  const [phase, setPhase] = useState('attacking');
  const [revealedCount, setRevealedCount] = useState(0);

  useEffect(() => {
    if (phase === 'complete') return undefined;
    const timer = window.setTimeout(() => {
      if (phase === 'attacking') setPhase('revealing');
      else if (revealedCount < revealSequence.length) setRevealedCount((count) => count + 1);
      else setPhase('complete');
    }, phase === 'attacking' ? 1100 : revealedCount < revealSequence.length ? 750 : 800);
    return () => window.clearTimeout(timer);
  }, [phase, revealedCount, revealSequence.length]);

  const visibleItems = revealSequence.slice(0, revealedCount);

  return (
    <div className="investigation-screen">
      <ViewHeader label="ADVERSARIAL REVIEW" onBack={onBack} onReturn={onReturn} />
      <main className="investigation-main">
        <section className="investigation-intro"><p className="eyebrow">CASE {result.case_id} / STAGE 04</p><h1>Devil&apos;s Advocate</h1><p className="investigation-intro-copy">{phase === 'attacking' ? 'ATTACKING THE PRELIMINARY VERDICT' : 'Attempting to challenge the preliminary assessment...'}</p></section>
        <section className="agent-pipeline devil-output"><div className="pipeline-heading"><span>{phase === 'attacking' ? '⚔ ATTACKING THE PRELIMINARY VERDICT' : `DEVIL&apos;S ADVOCATE / ${phase === 'complete' ? 'COMPLETE' : 'ANALYZING...'}`}</span><span className="active-label">{revealedCount} / {revealSequence.length} ITEMS</span></div><div className="devil-sequence">{visibleItems.map((entry, index) => <div className="devil-sequence-item" key={`${entry.type}-${entry.number}-${index}`}><p className="output-label">{entry.type === 'challenge' ? `CHALLENGE ${String(entry.number).padStart(2, '0')}` : 'COUNTER-EVIDENCE'}</p><FindingList items={[entry.item]} visibleCount={1} /></div>)}</div>{phase === 'complete' && <><p className="completion-label">✓ DEVIL&apos;S ADVOCATE COMPLETE</p><button className="continue-investigation-button" type="button" onClick={onContinue}>Continue to Judge <span aria-hidden="true">-&gt;</span></button></>}</section>
      </main>
    </div>
  );
}

function JudgeTransition({ onComplete }) {
  useEffect(() => {
    const timer = window.setTimeout(onComplete, 1800);
    return () => window.clearTimeout(timer);
  }, [onComplete]);

  return <div className="investigation-screen"><main className="judge-transition"><span className="judge-mark" aria-hidden="true">J</span><p className="eyebrow">STAGE 05 / FINAL REVIEW</p><h1>Judge</h1><h2>Awaiting verdict</h2><p>The evidence has been reviewed.<br />The investigator findings have been assembled.<br />The Devil&apos;s Advocate challenges have been considered.</p><div className="processing-checks"><span>Evidence reviewed ✓</span><span>Investigators complete ✓</span><span>Devil&apos;s Advocate complete ✓</span></div><span className="awaiting-label">AWAITING...</span></main></div>;
}

function JudgePage({ result, onBack, onReturn }) {
  const reasoning = result.verdict?.reasoning || [];
  const recommendations = result.verdict?.recommended_actions || [];
  const [reviewing, setReviewing] = useState(true);
  const [visibleReasoning, setVisibleReasoning] = useState(0);
  const [showRecommendations, setShowRecommendations] = useState(false);
  const [visibleRecommendations, setVisibleRecommendations] = useState(0);
  const reasoningComplete = !reviewing && visibleReasoning >= reasoning.length;

  useEffect(() => {
    const timer = window.setTimeout(() => setReviewing(false), 1000);
    return () => window.clearTimeout(timer);
  }, []);
  useEffect(() => {
    if (reviewing || visibleReasoning >= reasoning.length) return undefined;
    const timer = window.setTimeout(() => setVisibleReasoning((count) => count + 1), 650);
    return () => window.clearTimeout(timer);
  }, [reasoning.length, reviewing, visibleReasoning]);
  useEffect(() => {
    if (!showRecommendations || visibleRecommendations >= recommendations.length) return undefined;
    const timer = window.setTimeout(() => setVisibleRecommendations((count) => count + 1), 650);
    return () => window.clearTimeout(timer);
  }, [recommendations.length, showRecommendations, visibleRecommendations]);

  return <div className="investigation-screen"><ViewHeader label="FINAL ASSESSMENT" onBack={onBack} onReturn={onReturn} /><main className="investigation-main"><section className="investigation-intro"><p className="eyebrow">CASE {result.case_id} / STAGE 05</p><h1>{reviewing ? 'Judge' : reasoningComplete ? 'Final verdict' : 'Judge'}</h1><p className="investigation-intro-copy">{reviewing ? 'Reviewing evidence...' : reasoningComplete ? 'The Judge considered investigator evidence, findings, challenges and counter-evidence.' : 'Reviewing reasoning...'}</p></section>{!reviewing && <section className="final-verdict-panel">{reasoningComplete && <div className="verdict-summary"><span className="output-label">RISK LEVEL</span><strong>{result.verdict.risk_level}</strong><span>{(result.verdict.confidence * 100).toFixed(1)}% confidence</span></div>}<div className="verdict-columns"><div><p className="output-label">REASONING</p><FindingList items={reasoning} visibleCount={visibleReasoning} /></div><div><p className="output-label">REVIEW BASIS</p><p className="stage-empty">Investigator evidence reviewed.<br />Devil&apos;s Advocate challenges considered.<br />Counter-evidence considered.</p></div></div>{reasoningComplete && !showRecommendations && <button className="continue-investigation-button" type="button" onClick={() => setShowRecommendations(true)}>View Recommendations <span aria-hidden="true">-&gt;</span></button>}{showRecommendations && <div className="recommendations-output"><p className="output-label">RECOMMENDED ACTIONS</p><FindingList items={recommendations} visibleCount={visibleRecommendations} /></div>}</section>}</main></div>;
}

function App() {
  const [evidenceType, setEvidenceType] = useState('text');
  const [evidenceContent, setEvidenceContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [view, setView] = useState('landing');
  const returnToLanding = () => { setView('landing'); setResult(null); };

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
      setView('investigation');
    } catch (err) {
      setError('Failed to submit investigation. Please try again.');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  if (view === 'investigation' && result) {
    return <InvestigationPage result={result} onContinue={() => setView('devil')} onBack={returnToLanding} onReturn={returnToLanding} />;
  }

  if (view === 'devil' && result) {
    return <DevilsAdvocatePage result={result} onContinue={() => setView('judge-transition')} onBack={() => setView('investigation')} onReturn={returnToLanding} />;
  }

  if (view === 'judge-transition' && result) {
    return <JudgeTransition onComplete={() => setView('judge')} />;
  }

  if (view === 'judge' && result) {
    return <JudgePage result={result} onBack={() => setView('devil')} onReturn={returnToLanding} />;
  }

  return (
    <div className="App">
      <header className="app-header">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">T</span>
          <span className="brand-name">TRACE</span>
        </div>
        <div className="header-status">
          <span className="status-dot" aria-hidden="true" />
          <span>Investigation system online</span>
        </div>
      </header>

      <main>
        <section className="hero-copy">
          <p className="eyebrow">MULTI-AGENT CYBERSECURITY ANALYSIS</p>
          <h1>Don't just detect.<br /><span>Investigate.</span></h1>
          <p className="hero-description">
            Submit suspicious digital evidence and TRACE will examine it from
            multiple angles before delivering an evidence-backed assessment.
          </p>
          <div className="hero-meta" aria-hidden="true">
            <span className="hero-meta-line" />
            <span>INTAKE PROTOCOL / 01</span>
            <span>TRACE SYSTEM</span>
          </div>
        </section>

        <div className="forensic-search" aria-hidden="true">
          <div className="search-reveal">
            <span>REF / 0x_</span>
            <span>case.archive</span>
            <span>••• 01:17:—</span>
            <span>trace://unknown</span>
          </div>
          <div className="search-lens" />
          <div className="search-handle" />
        </div>

        <section className="investigation-form" aria-labelledby="submit-evidence-heading">
          <div className="section-heading">
            <div>
              <p className="section-kicker">NEW INVESTIGATION</p>
              <h2 id="submit-evidence-heading">Submit evidence</h2>
            </div>
            <div className="console-label">
              <span className="secure-badge">SECURE INTAKE</span>
              <span className="console-index">01 / 03</span>
            </div>
          </div>

          <div className="case-file-meta" aria-hidden="true">
            <span><b>CASE FILE</b> UNASSIGNED</span>
            <span><b>EVIDENCE</b> 01</span>
            <span><b>STATUS</b> AWAITING INTAKE</span>
          </div>

          <form onSubmit={handleSubmit}>
            <fieldset className="evidence-type-fieldset">
              <legend>Evidence type</legend>
              <div className="evidence-type-options">
                <button
                  type="button"
                  className={`evidence-type-option ${evidenceType === 'text' ? 'selected' : ''}`}
                  onClick={() => setEvidenceType('text')}
                  aria-pressed={evidenceType === 'text'}
                >
                  <span className="type-icon" aria-hidden="true">TXT</span>
                  <span>
                    <strong>Text</strong>
                    <small>Messages, emails, notes</small>
                  </span>
                  <span className="selection-indicator" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className={`evidence-type-option ${evidenceType === 'image' ? 'selected' : ''}`}
                  onClick={() => setEvidenceType('image')}
                  aria-pressed={evidenceType === 'image'}
                >
                  <span className="type-icon" aria-hidden="true">IMG</span>
                  <span>
                    <strong>Image</strong>
                    <small>Base64 screenshots</small>
                  </span>
                  <span className="selection-indicator" aria-hidden="true" />
                </button>
                <button
                  type="button"
                  className={`evidence-type-option ${evidenceType === 'url' ? 'selected' : ''}`}
                  onClick={() => setEvidenceType('url')}
                  aria-pressed={evidenceType === 'url'}
                >
                  <span className="type-icon" aria-hidden="true">URL</span>
                  <span>
                    <strong>URL</strong>
                    <small>Links and domains</small>
                  </span>
                  <span className="selection-indicator" aria-hidden="true" />
                </button>
              </div>
            </fieldset>

            <div className="evidence-content-field">
              <label htmlFor="evidence-content">Evidence content</label>
              <span className="field-reference" aria-hidden="true">REF / RAW SOURCE MATERIAL</span>
              <textarea
                id="evidence-content"
                value={evidenceContent}
                onChange={(e) => setEvidenceContent(e.target.value)}
                placeholder={
                  evidenceType === 'text'
                    ? 'Paste the suspicious message or communication here...'
                    : evidenceType === 'image'
                      ? 'Paste the base64-encoded image here...'
                      : 'Paste the suspicious URL here...'
                }
                rows={8}
                required
              />
              <div className="input-meta">
                <span>Analysis begins when you submit</span>
                <span className="character-count">{evidenceContent.length} characters</span>
              </div>
            </div>

            <div className="form-actions">
              <p className="privacy-note"><span aria-hidden="true">●</span> Evidence is handled as a private investigation</p>
              <button className="submit-button" type="submit" disabled={loading}>
                <span>{loading ? 'Investigating...' : 'Start Investigation'}</span>
                {!loading && <span className="button-arrow" aria-hidden="true">-&gt;</span>}
              </button>
            </div>
          </form>
          {error && <p className="error">{error}</p>}
        </section>

      </main>

      <footer className="app-footer">
        <p>TRACE - Multi-Agent AI Cybersecurity Investigation System</p>
      </footer>
    </div>
  );
}

export default App;