
import { Fragment, useEffect, useMemo, useState } from 'react';

const navItems = [
  'Dashboard',
  'Protected Environments',
  'Threat Detection',
  'Threat Simulation Lab',
  'Attack Intelligence',
  'AI Security Copilot',
  'Quantum Security',
  'AI Analytics',
  'Network Security',
  'Endpoint Security',
  'Cloud Security',
  'Application Security',
  'Cryptography',
  'Incident Response',
  'Security Events',
  'Risk Analysis',
  'Reports',
  'Integrations',
  'Settings',
];

const demoAccounts = {
  admin: { email: 'admin@quantumcyberdefense.demo', password: 'admin123' },
  customer: { email: 'customer@quantumcyberdefense.demo', password: 'customer123' },
};

const customerAllowedPages = navItems;

const defaultProtectedEnvironments = [
  { id: 'windows', name: 'Windows', type: 'Windows', threats: 3, status: 'Protected', integration: 'Install Endpoint Agent' },
  { id: 'linux', name: 'Linux Server', type: 'Linux', threats: 1, status: 'Protected', integration: 'Deploy Security Agent' },
  { id: 'cloud', name: 'Cloud', type: 'Cloud', threats: 7, status: 'Protected', integration: 'Connect Cloud Security API' },
  { id: 'web', name: 'Web Application', type: 'Web Application', threats: 0, status: 'Protected', integration: 'Install Web Security SDK / configure API' },
];

const environmentOptions = [
  { id: 'website', name: 'Website', integration: 'Install Web Security SDK / configure API' },
  { id: 'webapp', name: 'Web Application', integration: 'Connect application telemetry and WAF events' },
  { id: 'windows', name: 'Windows', integration: 'Install endpoint protection agent' },
  { id: 'linux', name: 'Linux', integration: 'Install Security Agent' },
  { id: 'macos', name: 'macOS', integration: 'Deploy managed endpoint telemetry' },
  { id: 'mobile', name: 'Mobile', integration: 'Connect mobile SDK and device posture data' },
  { id: 'cloud', name: 'Cloud', integration: 'Connect Cloud Security API' },
  { id: 'server', name: 'Server', integration: 'Deploy server-side logging and agent' },
  { id: 'api', name: 'API', integration: 'Configure API Gateway and auth logs' },
  { id: 'database', name: 'Database', integration: 'Enable SQL audit and access monitoring' },
  { id: 'iot', name: 'IoT', integration: 'Connect sensor telemetry and OT controls' },
  { id: 'network', name: 'Network', integration: 'Configure Sensor / Syslog / network telemetry' },
  { id: 'container', name: 'Container', integration: 'Attach runtime security to the cluster' },
  { id: 'vm', name: 'Virtual Machine', integration: 'Install host security monitor' },
  { id: 'custom', name: 'Custom', integration: 'Use custom API, webhook, or agent integration' },
];

const severityLevels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const incidentStatuses = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'];

const responsePlaybooks = [
  {
    matches: ['brute force', 'credential stuffing'],
    reason: 'Repeated authentication failures suggest password guessing or reused credentials.',
    action: 'Contain the source and protect affected identities.',
    steps: ['Block or rate-limit the source at the edge.', 'Reset affected credentials and require MFA.', 'Review sign-in logs and revoke suspicious sessions.'],
  },
  {
    matches: ['dos', 'ddos', 'denial of service'],
    reason: 'A sudden request or packet surge can exhaust service capacity.',
    action: 'Protect availability while identifying the traffic source.',
    steps: ['Apply upstream filtering or managed DDoS protection.', 'Rate-limit affected endpoints and preserve service health metrics.', 'Verify recovery and retain traffic samples for follow-up.'],
  },
  {
    matches: ['port scan', 'scan'],
    reason: 'Repeated connection attempts across ports may indicate service discovery before intrusion.',
    action: 'Restrict unnecessary exposure and monitor the source.',
    steps: ['Block the source if scanning is unauthorized.', 'Confirm exposed services and close unused ports.', 'Review subsequent authentication and exploit activity.'],
  },
];

const normalizeIncident = (incident) => ({
  ...incident,
  threatType: incident.threat_type ?? incident.threatType,
  detectedAt: incident.detected_at ?? incident.detectedAt,
  riskScore: incident.risk_score ?? incident.riskScore,
  assignedAnalyst: incident.assigned_analyst ?? incident.assignedAnalyst,
});

const statusColors = {
  OPEN: 'bg-red-500/15 text-red-300 border-red-500/50',
  INVESTIGATING: 'bg-amber-500/15 text-amber-300 border-amber-500/50',
  CONTAINED: 'bg-orange-500/15 text-orange-300 border-orange-500/50',
  RESOLVED: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/50',
  VALID: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/50',
  INVALID: 'bg-red-500/15 text-red-300 border-red-500/50',
  CRITICAL: 'bg-red-500/15 text-red-300 border-red-500/50',
  HIGH: 'bg-orange-500/15 text-orange-300 border-orange-500/50',
  MEDIUM: 'bg-amber-500/15 text-amber-300 border-amber-500/50',
  LOW: 'bg-emerald-500/15 text-emerald-300 border-emerald-500/50',
  default: 'bg-slate-700/50 text-slate-200 border-slate-500/50',
};

function App() {
  const [page, setPage] = useState('Dashboard');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [aiStatus, setAiStatus] = useState(null);
  const [analyticsData, setAnalyticsData] = useState(null);
  const [analyticsError, setAnalyticsError] = useState('');
  const [copilotScope, setCopilotScope] = useState('Dashboard');
  const [copilotQuestion, setCopilotQuestion] = useState('');
  const [copilotAnswer, setCopilotAnswer] = useState(null);
  const [isCopilotLoading, setIsCopilotLoading] = useState(false);
  const [simulationScenarios, setSimulationScenarios] = useState([]);
  const [simulationConfig, setSimulationConfig] = useState({
    scenario_id: 'universal-cross-platform',
    target_platform: 'linux',
    severity: 'HIGH',
    protocol: 'TCP',
    timestamp_pattern: 'SEQUENTIAL',
    event_volume: 47,
    duration_seconds: 60,
    difficulty: 'MEDIUM',
    attacker_identity: 'demo_attacker_01',
    target_identity: 'demo_user_01',
    use_ai_analysis: true,
  });
  const [activeSimulation, setActiveSimulation] = useState(null);
  const [simulationError, setSimulationError] = useState('');
  const [isStartingSimulation, setIsStartingSimulation] = useState(false);
  const [selectedSimulationEvent, setSelectedSimulationEvent] = useState(null);
  const [simulationActionResult, setSimulationActionResult] = useState(null);
  const [customScenarioName, setCustomScenarioName] = useState('');
  const [customScenarioCategory, setCustomScenarioCategory] = useState('NETWORK');
  const [customScenarioPlatform, setCustomScenarioPlatform] = useState('linux');
  const [customScenarioSequence, setCustomScenarioSequence] = useState(['port_scan', 'authentication_failure', 'privilege_escalation']);
  const [customScenarioStage, setCustomScenarioStage] = useState('lateral_movement');
  const [customScenarioNoise, setCustomScenarioNoise] = useState('MEDIUM');
  const [customExpectedDetection, setCustomExpectedDetection] = useState('Credential abuse followed by privilege and data access');
  const [customExpectedMitre, setCustomExpectedMitre] = useState('T1110 - Brute Force');
  const [customExpectedResponse, setCustomExpectedResponse] = useState('Review synthetic evidence and simulate account containment');
  const [reportGeneratedAt, setReportGeneratedAt] = useState(() => new Date());
  const [authToken, setAuthToken] = useState('');
  const [userRole, setUserRole] = useState('admin');
  const [authMode, setAuthMode] = useState('login');
  const [loginView, setLoginView] = useState('admin');
  const [loginForm, setLoginForm] = useState(demoAccounts.admin);
  const [otpPrompt, setOtpPrompt] = useState(false);
  const [otpCode, setOtpCode] = useState('');
  const [otpResendDelay, setOtpResendDelay] = useState(0);
  const [otpResendVisible, setOtpResendVisible] = useState(false);
  const [isResendingOtp, setIsResendingOtp] = useState(false);
  const [pendingLogin, setPendingLogin] = useState(null);
  const [registerForm, setRegisterForm] = useState({ name: 'Security Analyst', email: '', password: '' });
  const [liveMonitoring, setLiveMonitoring] = useState(false);
  const [liveThreats, setLiveThreats] = useState([]);
  const [websiteSources, setWebsiteSources] = useState([]);
  const [websiteForm, setWebsiteForm] = useState({ name: '', url: '' });
  const [createdWebsite, setCreatedWebsite] = useState(null);
  const [isAddingWebsite, setIsAddingWebsite] = useState(false);
  const [protectedEnvironments, setProtectedEnvironments] = useState(defaultProtectedEnvironments);
  const [showAddEnvironment, setShowAddEnvironment] = useState(false);
  const [selectedEnvironmentType, setSelectedEnvironmentType] = useState(environmentOptions[0].name);
  const [threats, setThreats] = useState([
    { id: 'THR-1042', source: '192.168.x.x', classification: 'Brute Force', risk: 91, confidence: 'Rule-based', severity: 'Critical', status: 'UNSIGNED' },
    { id: 'THR-1043', source: '203.0.113.x', classification: 'Port Scan', risk: 74, confidence: 'Rule-based', severity: 'High', status: 'UNSIGNED' },
    { id: 'THR-1044', source: '198.51.100.x', classification: 'DoS/DDoS', risk: 88, confidence: 'Rule-based', severity: 'Critical', status: 'UNSIGNED' },
  ]);
  const [threatResult, setThreatResult] = useState(null);
  const [processingStatus, setProcessingStatus] = useState('Awaiting threat analysis');
  const [isProcessing, setIsProcessing] = useState(false);
  const [auditLogs, setAuditLogs] = useState([
    { timestamp: '2026-09-25 15:30:12', user: 'Security Analyst', action: 'Analyst logged in', resource: 'Login', eventId: 'SYS-LOGIN', signatureStatus: 'N/A' },
    { timestamp: '2026-09-25 15:31:04', user: 'Security Analyst', action: 'Threat analyzed', resource: 'Threat Detection', eventId: 'THR-1042', signatureStatus: 'UNSIGNED' },
    { timestamp: '2026-09-25 15:31:06', user: 'Security Analyst', action: 'Incident created', resource: 'Incidents', eventId: 'INC-3001', signatureStatus: 'UNSIGNED' },
  ]);
  const [incidentList, setIncidentList] = useState([
    { id: 'INC-3001', threatType: 'Brute Force', severity: 'CRITICAL', source: '192.168.10.12', detectedAt: '2026-09-25T15:31:06Z', riskScore: 91, confidence: 96.2, status: 'OPEN', assignedAnalyst: 'Security Analyst' },
  ]);
  const [updatingIncidentId, setUpdatingIncidentId] = useState(null);
  const [signatureState, setSignatureState] = useState({
    valid: false,
    hash: 'Not signed',
    signature: 'Not signed',
    status: 'UNSIGNED',
    eventId: 'N/A',
    signedAt: 'N/A',
    keyMode: 'N/A',
    tamperedEvent: null,
  });
  const isAdmin = userRole === 'admin';

  useEffect(() => {
    if (!isLoggedIn) return;

    setReportGeneratedAt(new Date());
    const interval = setInterval(() => setReportGeneratedAt(new Date()), 60000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn) return;

    let cancelled = false;
    const loadAnalytics = async () => {
      try {
        const response = await fetch('/api/analytics');
        if (!response.ok) throw new Error('Unable to load live analytics');
        const data = await response.json();
        if (!cancelled) {
          setAnalyticsData(data);
          setAnalyticsError('');
        }
      } catch (error) {
        if (!cancelled) setAnalyticsError(error.message || 'Analytics service unavailable');
      }
    };

    loadAnalytics();
    const interval = setInterval(loadAnalytics, 2000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn || !authToken) return;

    let cancelled = false;
    fetch('/api/ai/status', { headers: { Authorization: `Bearer ${authToken}` } })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Unable to load AI status')))
      .then((data) => { if (!cancelled) setAiStatus(data); })
      .catch(() => { if (!cancelled) setAiStatus(null); });

    return () => { cancelled = true; };
  }, [isLoggedIn, authToken]);

  useEffect(() => {
    if (!isLoggedIn || !isAdmin || !authToken) return;

    fetch('/api/simulations/scenarios', { headers: { Authorization: `Bearer ${authToken}` } })
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Unable to load simulation scenarios')))
      .then((data) => setSimulationScenarios(data.items || []))
      .catch((error) => setSimulationError(error.message || 'Simulation API unavailable'));
  }, [isLoggedIn, isAdmin, authToken]);

  useEffect(() => {
    if (!isLoggedIn || !isAdmin || !authToken || activeSimulation?.status !== 'running') return;

    let cancelled = false;
    const pollSimulation = async () => {
      try {
        const response = await fetch(`/api/simulations/runs/${encodeURIComponent(activeSimulation.id)}`, {
          headers: { Authorization: `Bearer ${authToken}` },
        });
        if (!response.ok) throw new Error('Unable to load simulation progress');
        const data = await response.json();
        if (!cancelled) setActiveSimulation(data);
      } catch (error) {
        if (!cancelled) setSimulationError(error.message || 'Simulation progress unavailable');
      }
    };

    const interval = setInterval(pollSimulation, 500);
    pollSimulation();
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [isLoggedIn, isAdmin, authToken, activeSimulation?.id, activeSimulation?.status]);

  useEffect(() => {
    if (!isLoggedIn) return;

    const loadLiveThreats = async () => {
      try {
        const response = await fetch('/api/threats/live');
        if (!response.ok) return;
        const data = await response.json();
        setLiveMonitoring(Boolean(data.monitoring));
        setLiveThreats(data.threats || []);
      } catch (error) {
        console.error('Unable to load live feed', error);
      }
    };

    loadLiveThreats();
    const interval = setInterval(loadLiveThreats, 2000);
    return () => clearInterval(interval);
  }, [isLoggedIn]);

  useEffect(() => {
    if (!isLoggedIn || userRole !== 'admin') return;
    fetch('/api/incidents')
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Unable to load incidents')))
      .then((data) => setIncidentList((data.items || []).map(normalizeIncident)))
      .catch((error) => console.error(error));
  }, [isLoggedIn, userRole]);

  useEffect(() => {
    if (!isLoggedIn) return;
    fetch('/api/sources/websites')
      .then((response) => response.ok ? response.json() : Promise.reject(new Error('Unable to load website sources')))
      .then((data) => setWebsiteSources(data.items || []))
      .catch((error) => console.error(error));
  }, [isLoggedIn]);

  const visibleNavItems = navItems;

  const timelineThreats = liveThreats.length ? liveThreats : threats;

  const securityMetrics = useMemo(() => {
    const riskItems = timelineThreats.map((item) => Number(item.risk_score ?? item.risk ?? 0));
    const avgRisk = riskItems.length ? Math.round(riskItems.reduce((sum, item) => sum + item, 0) / riskItems.length) : 0;
    const criticalThreats = timelineThreats.filter((item) => String(item.severity || '').toUpperCase() === 'CRITICAL').length;
    const highRiskSignals = timelineThreats.filter((item) => Number(item.risk_score ?? item.risk ?? 0) >= 75).length;
    const openIncidents = incidentList.filter((item) => !['RESOLVED', 'CLOSED'].includes(String(item.status || '').toUpperCase())).length;
    const verifiedEvents = signatureState.valid ? 1 : 0;

    return {
      avgRisk,
      criticalThreats,
      highRiskSignals,
      openIncidents,
      verifiedEvents,
      activeEnvironments: protectedEnvironments.length,
      score: 92,
    };
  }, [timelineThreats, incidentList, signatureState.valid, protectedEnvironments]);
  const severityColors = {
    CRITICAL: '#fb7185',
    HIGH: '#fb923c',
    MEDIUM: '#fbbf24',
    LOW: '#34d399',
    UNKNOWN: '#64748b',
  };
  const analyticsSeverityEntries = Object.entries(analyticsData?.severity_distribution || {})
    .filter(([, count]) => count > 0)
    .sort((left, right) => (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].indexOf(left[0]) - ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].indexOf(right[0])));
  const analyticsSeverityTotal = analyticsSeverityEntries.reduce((total, [, count]) => total + count, 0);
  let pieStart = 0;
  const analyticsPieBackground = analyticsSeverityTotal
    ? `conic-gradient(${analyticsSeverityEntries.map(([severity, count]) => {
      const start = pieStart;
      pieStart += count / analyticsSeverityTotal * 100;
      return `${severityColors[severity] || severityColors.UNKNOWN} ${start}% ${pieStart}%`;
    }).join(', ')})`
    : 'conic-gradient(#334155 0% 100%)';
  const analyticsBuckets = analyticsData?.threats_over_time || [];
  const analyticsBucketMax = Math.max(1, ...analyticsBuckets.map((bucket) => bucket.total || 0));
  const activityTimeline = [
    ...timelineThreats.map((item) => ({
      id: item.id,
      title: item.classification || 'Threat detected',
      detail: `${item.source || item.source_ip || 'Unknown source'} · ${item.severity || 'Unrated'}`,
      timestamp: item.detected_at || item.created_at || item.timestamp || '',
      kind: 'Threat',
    })),
    ...incidentList.map((item) => ({
      id: item.id,
      title: `Incident ${item.status?.toLowerCase() || 'opened'}`,
      detail: `${item.threatType || item.threat_type} · ${item.source}`,
      timestamp: item.detectedAt || item.detected_at || '',
      kind: 'Incident',
    })),
  ]
    .sort((left, right) => (Date.parse(right.timestamp) || 0) - (Date.parse(left.timestamp) || 0))
    .slice(0, 6);

  const prioritizedThreat = threatResult || [...liveThreats, ...threats]
    .sort((left, right) => (right.risk_score ?? right.risk ?? 0) - (left.risk_score ?? left.risk ?? 0))[0];
  const playbookType = String(prioritizedThreat?.classification || '').toLowerCase();
  const matchedPlaybook = responsePlaybooks.find((playbook) => playbook.matches.some((term) => playbookType.includes(term)));
  const activePlaybook = {
    reason: prioritizedThreat?.reason || matchedPlaybook?.reason || 'Review the event evidence and validate whether the activity is authorized.',
    action: prioritizedThreat?.recommended_action || matchedPlaybook?.action || 'Triage the source, preserve evidence, and confirm the affected service owner.',
    steps: prioritizedThreat?.remediation_steps || matchedPlaybook?.steps || ['Validate the source and event details.', 'Check related activity across affected services.', 'Document the outcome and escalate if impact is confirmed.'],
  };

  const updateIncident = async (incident, updates, actionName) => {
    setUpdatingIncidentId(incident.id);
    try {
      const response = await fetch(`/api/incidents/${encodeURIComponent(incident.id)}`, {
        method: 'PATCH',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify(updates),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || `Unable to ${actionName.toLowerCase()} incident`);

      const updatedIncident = normalizeIncident(data);
      setIncidentList((current) => current.map((item) => item.id === incident.id ? updatedIncident : item));
      setAuditLogs((current) => [{
        timestamp: new Date().toLocaleString(),
        user: 'Security Analyst',
        action: actionName,
        resource: 'Incidents',
        eventId: incident.id,
        signatureStatus: 'VALID',
      }, ...current]);
    } catch (error) {
      alert(error.message || `Unable to ${actionName.toLowerCase()} incident`);
    } finally {
      setUpdatingIncidentId(null);
    }
  };

  const currentPage = useMemo(() => {
    if (!isLoggedIn) return 'Login';
    if (!isAdmin && !customerAllowedPages.includes(page)) return 'Dashboard';
    return page;
  }, [isLoggedIn, page, isAdmin]);

  useEffect(() => {
    if (!isLoggedIn || isAdmin) return;
    if (!customerAllowedPages.includes(page)) {
      setPage('Dashboard');
    }
  }, [isLoggedIn, page, isAdmin]);

  const openCopilot = (scope, question = '') => {
    setCopilotScope(scope);
    setCopilotQuestion(question);
    setCopilotAnswer(null);
    setPage('AI Security Copilot');
    if (question) askCopilot(question, scope);
  };

  const askCopilot = async (question = copilotQuestion, scope = copilotScope) => {
    const trimmedQuestion = question.trim();
    if (trimmedQuestion.length < 3) return;

    setIsCopilotLoading(true);
    setCopilotAnswer(null);
    try {
      const response = await fetch('/api/ai/ask', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          question: trimmedQuestion,
          current_page: scope,
          context: {
            metrics: {
              security_score: securityMetrics.score,
              average_risk: securityMetrics.avgRisk,
              critical_threats: securityMetrics.criticalThreats,
              high_risk_signals: securityMetrics.highRiskSignals,
              open_incidents: securityMetrics.openIncidents,
              protected_environments: securityMetrics.activeEnvironments,
            },
            threats: timelineThreats.slice(0, 8).map((item) => ({
              classification: item.classification,
              severity: item.severity,
              risk_score: item.risk_score ?? item.risk,
              source: item.source || item.source_ip,
            })),
            incidents: incidentList.slice(0, 8).map((item) => ({
              id: item.id,
              type: item.threatType || item.threat_type,
              severity: item.severity,
              status: item.status,
            })),
            analytics: analyticsData ? {
              event_count: analyticsData.event_count,
              average_risk: analyticsData.average_risk,
              severity_distribution: analyticsData.severity_distribution,
              threats_over_time: analyticsData.threats_over_time,
            } : null,
            environments: protectedEnvironments.slice(0, 12).map((item) => ({
              name: item.name,
              type: item.type,
              status: item.status,
              threat_count: item.threats,
            })),
          },
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Llama request failed');
      setCopilotAnswer(data);
    } catch (error) {
      setCopilotAnswer({ answer: error.message || 'Unable to contact the security copilot.', provider: 'Unavailable', status: 'error' });
    } finally {
      setIsCopilotLoading(false);
    }
  };

  const submitCopilotQuestion = (event) => {
    event.preventDefault();
    askCopilot();
  };

  const startSimulation = async (scenarioId = simulationConfig.scenario_id, overrides = {}) => {
    if (!isAdmin || isStartingSimulation) return;
    setIsStartingSimulation(true);
    setSimulationError('');
    setSimulationActionResult(null);
    setSelectedSimulationEvent(null);
    try {
      const response = await fetch('/api/simulations/run', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          ...simulationConfig,
          ...overrides,
          scenario_id: scenarioId,
          use_ai_analysis: Boolean(aiStatus?.configured),
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Unable to start simulation');
      setActiveSimulation(data);
    } catch (error) {
      setSimulationError(error.message || 'Unable to start simulation');
    } finally {
      setIsStartingSimulation(false);
    }
  };

  const createCustomScenario = async () => {
    if (!isAdmin || !customScenarioName.trim()) return;
    setSimulationError('');
    try {
      const response = await fetch('/api/simulations/custom-scenarios', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          name: customScenarioName.trim(),
          category: customScenarioCategory,
          target_platform: customScenarioPlatform,
          event_sequence: customScenarioSequence,
          severity: simulationConfig.severity,
          event_volume: simulationConfig.event_volume,
          difficulty: simulationConfig.difficulty,
          noise_level: customScenarioNoise,
          expected_detection: customExpectedDetection,
          expected_mitre_mapping: customExpectedMitre,
          expected_response: customExpectedResponse,
        }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Unable to create custom scenario');
      setSimulationScenarios((items) => [...items, { ...data, custom: true }]);
      setSimulationConfig((current) => ({ ...current, scenario_id: data.id, target_platform: customScenarioPlatform }));
      setCustomScenarioName('');
    } catch (error) {
      setSimulationError(error.message || 'Unable to create custom scenario');
    }
  };

  const simulateResponseAction = async (action) => {
    if (!activeSimulation?.id) return;
    try {
      const response = await fetch(`/api/simulations/runs/${encodeURIComponent(activeSimulation.id)}/responses`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${authToken}`,
        },
        body: JSON.stringify({ action }),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Simulated response failed');
      setSimulationActionResult(data);
      setActiveSimulation((current) => ({ ...current, responses: [...(current.responses || []), data] }));
    } catch (error) {
      setSimulationError(error.message || 'Simulated response failed');
    }
  };

  useEffect(() => {
    if (otpResendDelay <= 0) return;

    const countdown = setTimeout(() => {
      setOtpResendDelay((current) => Math.max(current - 1, 0));
    }, 1000);

    return () => clearTimeout(countdown);
  }, [otpResendDelay]);

  const signIn = async (e) => {
    e.preventDefault();

    const email = loginForm.email.trim();
    const password = loginForm.password;
    const role = loginView;

    if (!email || !password) {
      alert('Please enter both your email and password.');
      return;
    }

    let response;
    try {
      response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, role }),
      });
    } catch {
      alert('Unable to reach the sign-in service. Please try again.');
      return;
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Invalid credentials for this login type' }));
      alert(error.detail || 'Invalid credentials for this login type');
      return;
    }

    const data = await response.json();
    if (data.requires_otp) {
      setPendingLogin({ email, role });
      setOtpPrompt(true);
      setOtpCode('');
      setOtpResendDelay(0);
      setOtpResendVisible(false);
      if (data.otp_code) {
        alert(`OTP generated for local testing (${role}): ${data.otp_code}`);
      } else {
        alert('OTP sent to your email. Please check your inbox and enter the code below.');
      }
      return;
    }

    setAuthToken(data.token || '');
    setUserRole(data.user?.role || role);
    setIsLoggedIn(true);
    setPage('Dashboard');
    setAuditLogs((prev) => [{ timestamp: new Date().toLocaleString(), user: data.user?.name || email, action: `${data.user?.role || role} logged in`, resource: 'Login', eventId: 'SYS-LOGIN', signatureStatus: 'VALID' }, ...prev]);
  };

  const verifyOtp = async (e) => {
    e.preventDefault();

    if (!pendingLogin) {
      setOtpPrompt(false);
      return;
    }

    const trimmedOtp = otpCode.trim();
    if (!trimmedOtp) {
      alert('Please enter the OTP sent to your device.');
      return;
    }

    try {
      const response = await fetch('/api/auth/verify-login-otp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: pendingLogin.email,
          password: loginForm.password,
          role: pendingLogin.role,
          otp: trimmedOtp,
        }),
      });

      if (!response.ok) {
        const error = await response.json().catch(() => ({ detail: 'Invalid OTP' }));
        setOtpResendDelay(20);
        setOtpResendVisible(true);
        setOtpCode('');
        alert(`${error.detail || 'Invalid OTP'}. You can request a new OTP in 20 seconds.`);
        return;
      }

      const data = await response.json();
      setOtpResendDelay(0);
      setOtpResendVisible(false);
      setAuthToken(data.token || '');
      setUserRole(data.user?.role || pendingLogin.role);
      setIsLoggedIn(true);
      setOtpPrompt(false);
      setOtpCode('');
      setPendingLogin(null);
      setPage('Dashboard');
      setAuditLogs((prev) => [{ timestamp: new Date().toLocaleString(), user: data.user?.name || pendingLogin.email, action: `${data.user?.role || pendingLogin.role} logged in with OTP verification`, resource: 'Login', eventId: 'SYS-LOGIN-OTP', signatureStatus: 'VALID' }, ...prev]);
    } catch {
      alert('Unable to verify the OTP. Please try again.');
    }
  };

  const resendOtp = async () => {
    if (!pendingLogin || otpResendDelay > 0 || isResendingOtp) return;

    setIsResendingOtp(true);
    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: pendingLogin.email,
          password: loginForm.password,
          role: pendingLogin.role,
        }),
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.requires_otp) {
        throw new Error('Unable to resend the OTP right now.');
      }

      setOtpCode('');
      setOtpResendDelay(20);
      setOtpResendVisible(true);
      if (data.otp_code) {
        alert(`New OTP generated for local testing (${pendingLogin.role}): ${data.otp_code}`);
      } else {
        alert('A new OTP has been sent to your email.');
      }
    } catch (error) {
      alert(error.message || 'Unable to resend OTP. Please try again.');
    } finally {
      setIsResendingOtp(false);
    }
  };

  const signUp = async (e) => {
    e.preventDefault();

    const name = registerForm.name.trim();
    const email = registerForm.email.trim().toLowerCase();
    const password = registerForm.password;

    if (!name || !email || !password) {
      alert('Please complete all sign-up fields.');
      return;
    }

    if (password.length < 8) {
      alert('Password must be at least 8 characters long.');
      return;
    }

    let response;
    try {
      response = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, email, password }),
      });
    } catch {
      alert('Unable to reach the registration service. Please try again.');
      return;
    }

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Registration failed' }));
      alert(error.detail || 'Registration failed');
      return;
    }

    const data = await response.json();
  setAuthToken('');
  setLoginView('customer');
    setLoginForm({ email: data.user.email, password });
    setRegisterForm({ name: 'Customer Portal', email: '', password: '' });
    setAuthMode('login');
  setPendingLogin(null);
  setOtpPrompt(false);
  setOtpCode('');
  setOtpResendVisible(false);
  setOtpResendDelay(0);
  alert('Account created. Sign in with your email and password to verify your account.');
  };

  const demoLoginAction = () => {
    const demo = demoAccounts[loginView] || demoAccounts.admin;
    setLoginForm(demo);
  };

  const changeLoginView = (role) => {
    setLoginView(role);
    setLoginForm((current) => {
      const isDemoAccount = Object.values(demoAccounts).some(
        (account) => account.email === current.email && account.password === current.password
      );
      return isDemoAccount ? demoAccounts[role] : current;
    });
  };

  const registerWebsite = async (event) => {
    event.preventDefault();
    setIsAddingWebsite(true);
    try {
      const response = await fetch('/api/sources/websites', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(websiteForm),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Website registration failed');
      setCreatedWebsite(data);
      setWebsiteSources((current) => [data, ...current]);
      setWebsiteForm({ name: '', url: '' });
    } catch (error) {
      alert(error.message || 'Website registration failed');
    } finally {
      setIsAddingWebsite(false);
    }
  };

  const addProtectedEnvironment = (environmentType) => {
    const option = environmentOptions.find((item) => item.name === environmentType) || environmentOptions[0];
    const nextEnvironment = {
      id: `${option.id}-${Date.now()}`,
      name: option.name === 'Custom' ? 'Custom Integration' : option.name,
      type: option.name,
      status: 'Protected',
      threats: Math.floor(Math.random() * 6),
      integration: option.integration,
    };
    setProtectedEnvironments((current) => [nextEnvironment, ...current]);
    setSelectedEnvironmentType(option.name);
    setShowAddEnvironment(false);
  };

  const handleLayoutPointerMove = (event) => {
    const element = event.currentTarget;
    const rect = element.getBoundingClientRect();
    const offsetX = (event.clientX - (rect.left + rect.width / 2)) / 16;
    const offsetY = (event.clientY - (rect.top + rect.height / 2)) / 16;

    element.style.setProperty('--pointer-x', `${offsetX}px`);
    element.style.setProperty('--pointer-y', `${offsetY}px`);
  };

  const handleBackToLogin = () => {
    setIsLoggedIn(false);
    setAuthToken('');
    setOtpPrompt(false);
    setOtpCode('');
    setOtpResendVisible(false);
    setOtpResendDelay(0);
    setPendingLogin(null);
    setPage('Dashboard');
    setLoginForm(demoAccounts.admin);
    setAuthMode('login');
    setLoginView('admin');
  };

  const toggleMonitoring = async () => {
    const nextState = !liveMonitoring;
    try {
      const response = await fetch('/api/threats/monitoring', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: nextState }),
      });
      const data = await response.json();
      setLiveMonitoring(Boolean(data.monitoring));
      setLiveThreats(data.threats || []);
    } catch (error) {
      console.error('Unable to toggle monitoring', error);
    }
  };

  const analyzeThreat = async () => {
    const payload = {
      source_ip: '203.0.113.27',
      destination_ip: '10.0.0.5',
      protocol: 'TCP',
      source_port: 52144,
      destination_port: 80,
      packet_count: 2400,
      bytes_sent: 160000,
      bytes_received: 50000,
      connection_duration: 120,
      failed_login_attempts: 12,
      request_frequency: 68,
    };

    setIsProcessing(true);
    setProcessingStatus('Running quantum-inspired optimization and anomaly classification...');

    try {
      const response = await fetch('/api/threats/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) {
        throw new Error(data.detail || 'Threat analysis failed');
      }

      setThreatResult(data);
      setProcessingStatus('Threat classified. Preparing digital signature...');

      const signaturePayload = {
        event_id: data.id,
        event_data: { ...data.event_data, risk_score: data.risk_score },
      };

      const signatureResponse = await fetch('/api/signatures/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signaturePayload),
      });
      const signatureData = await signatureResponse.json();
      if (!signatureResponse.ok) {
        throw new Error(signatureData.detail || 'Signature generation failed');
      }

      setSignatureState({
        valid: true,
        hash: signatureData.hash,
        signature: signatureData.signature,
        status: 'VALID',
        eventId: data.id,
        signedAt: signatureData.signed_at,
        keyMode: signatureData.key_mode,
        tamperedEvent: null,
      });
      setProcessingStatus('Quantum threat detection complete and digital signature generated successfully.');
      setAuditLogs((prev) => [
        { timestamp: new Date().toLocaleString(), user: 'Security Analyst', action: 'Threat analyzed', resource: 'Threat Detection', eventId: data.id, signatureStatus: 'VALID' },
        { timestamp: new Date().toLocaleString(), user: 'Security Analyst', action: 'Digital signature generated', resource: 'Digital Signature', eventId: data.id, signatureStatus: 'VALID' },
        ...prev,
      ]);
    } catch (error) {
      setProcessingStatus(error.message || 'Threat analysis failed.');
      alert(error.message || 'Threat analysis failed.');
    } finally {
      setIsProcessing(false);
    }
  };

  const verifyThreat = async () => {
    if (!threatResult || signatureState.signature === 'Not signed') return;
    const payload = {
      event_id: threatResult.id,
      event_data: signatureState.tamperedEvent || { ...threatResult.event_data, risk_score: threatResult.risk_score },
    };
    try {
      const response = await fetch('/api/signatures/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Evidence verification failed');
      setSignatureState((previous) => ({
        ...previous,
        valid: Boolean(data.verified),
        hash: data.hash || previous.hash,
        signature: data.signature || previous.signature,
        status: data.verified ? 'VALID' : 'INVALID',
      }));
      setAuditLogs((previous) => [{ timestamp: new Date().toLocaleString(), user: 'Security Analyst', action: 'Evidence verified', resource: 'Digital Signature', eventId: threatResult.id, signatureStatus: data.verified ? 'VALID' : 'INVALID' }, ...previous]);
    } catch (error) {
      alert(error.message || 'Evidence verification failed');
    }
  };

  const tamperThreat = async () => {
    if (!threatResult || signatureState.signature === 'Not signed') return;
    const payload = {
      event_id: threatResult.id,
      event_data: { ...threatResult.event_data, risk_score: threatResult.risk_score },
    };
    try {
      const response = await fetch('/api/signatures/tamper', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Tamper simulation failed');
      setSignatureState((previous) => ({
        ...previous,
        valid: false,
        hash: data.tampered_hash || previous.hash,
        status: data.status || 'INVALID',
        eventId: threatResult.id,
        tamperedEvent: data.tampered_event,
      }));
      setAuditLogs((previous) => [{ timestamp: new Date().toLocaleString(), user: 'Security Analyst', action: 'Tamper simulation executed', resource: 'Digital Signature', eventId: payload.event_id, signatureStatus: 'INVALID' }, ...previous]);
    } catch (error) {
      alert(error.message || 'Tamper simulation failed');
    }
  };

  const createIncident = async () => {
    if (!threatResult) return;
    const payload = {
      threat_id: threatResult.id,
      threat_type: threatResult.classification,
      severity: threatResult.severity,
      source: threatResult.source_ip,
      risk_score: threatResult.risk_score,
      confidence: threatResult.confidence,
      status: 'OPEN',
      assigned_analyst: 'Security Analyst',
    };
    const response = await fetch('/api/incidents', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    setIncidentList((prev) => [
      {
        id: data.id,
        threatType: data.threat_type,
        severity: data.severity,
        source: data.source,
        detectedAt: data.detected_at,
        riskScore: data.risk_score,
        confidence: data.confidence,
        status: data.status,
        assignedAnalyst: data.assigned_analyst,
      },
      ...prev,
    ]);
  };

  const renderPage = () => {
    const reportThreatCount = timelineThreats.length;
    const invoiceBaselineThreatCount = 3;
    const baseInvoiceLines = [
      ['Universal Security Gateway', 0.0126],
      ['Threat Intelligence Engine', 0.0108],
      ['Quantum-Inspired Analysis', 0.0153],
      ['Incident Response Coverage', 0.0186],
      ['Cloud + Endpoint Protection', 0.0162],
    ];
    const reportInvoiceTotal = baseInvoiceLines.reduce((total, [, amount]) => total + amount, 0)
      * reportThreatCount / invoiceBaselineThreatCount;

    if (!isLoggedIn) {
      return (
        <div
          className="login-shell"
          onMouseMove={handleLayoutPointerMove}
        >
          <div className="login-orb login-orb--one" />
          <div className="login-orb login-orb--two" />

          <div className="login-card glass-panel" style={{ maxWidth: 460, width: '100%' }}>
            <div className="login-card__header" style={{ marginBottom: 18, textAlign: 'center' }}>
              <div className="login-logo-wrap">
                <img className="login-logo" src="/quantum-cyber-defense-shield.svg" alt="Quantum Cyber Defense shield" />
              </div>
              <h1 style={{ letterSpacing: '0.04em', margin: '0 0 8px', textAlign: 'center' }}>QUANTUM CYBER TDS</h1>
              <p style={{ margin: 0, color: '#cbd5e1', textAlign: 'center' }}>Secure operations, trusted intelligence, protected integrity</p>
            </div>

            {authMode === 'login' ? (
              <>
                <form onSubmit={otpPrompt ? verifyOtp : signIn} className="login-form">
                  <div className="field-block">
                    <label>Email</label>
                    <input
                      value={loginForm.email}
                      onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })}
                      type="email"
                      placeholder="you@example.com"
                      disabled={otpPrompt}
                    />
                  </div>

                  <div className="field-block">
                    <label>Password</label>
                    <input
                      value={loginForm.password}
                      onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
                      type="password"
                      placeholder="••••••••"
                      disabled={otpPrompt}
                    />
                  </div>

                  {otpPrompt && (
                    <>
                      <div className="field-block">
                        <label>OTP verification</label>
                        <input
                          value={otpCode}
                          onChange={(e) => setOtpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                          type="text"
                          inputMode="numeric"
                          placeholder="123456"
                          autoComplete="one-time-code"
                        />
                      </div>

                      {otpResendVisible && (
                        <div style={{ marginTop: 10, textAlign: 'center' }}>
                          <button
                            type="button"
                            className="text-link"
                            onClick={resendOtp}
                            disabled={otpResendDelay > 0 || isResendingOtp}
                          >
                            {isResendingOtp
                              ? 'Sending new OTP...'
                              : otpResendDelay > 0
                                ? `Resend OTP in ${otpResendDelay}s`
                                : 'Resend OTP'}
                          </button>
                        </div>
                      )}
                    </>
                  )}

                  <div style={{ display: 'flex', gap: 10, flexDirection: 'column' }}>
                    <button type="submit" className="primary-btn w-full" style={{ marginTop: 6 }}>
                      {otpPrompt ? 'Verify OTP & Sign In' : 'Sign In'}
                    </button>
                    {otpPrompt && (
                      <button
                        type="button"
                        className="secondary-btn w-full"
                        onClick={() => {
                          setOtpPrompt(false);
                          setOtpCode('');
                          setPendingLogin(null);
                        }}
                      >
                        Back to login
                      </button>
                    )}
                  </div>
                </form>

                <div className="auth-footer">
                  <div className="auth-switcher auth-switcher--footer">
                    <button type="button" className={loginView === 'admin' ? 'auth-option auth-option--active' : 'auth-option'} onClick={() => changeLoginView('admin')} disabled={otpPrompt}>Admin</button>
                    <button type="button" className={loginView === 'customer' ? 'auth-option auth-option--active' : 'auth-option'} onClick={() => changeLoginView('customer')} disabled={otpPrompt}>Customer</button>
                  </div>

                  <div className="auth-meta-row">
                    <button type="button" className="text-link" onClick={() => setAuthMode('register')}>Register</button>
                    <button type="button" className="text-link" onClick={demoLoginAction}>Use demo account</button>
                  </div>
                </div>
              </>
            ) : (
              <form onSubmit={signUp} className="login-form">
                <div className="field-block">
                  <label>Name</label>
                  <input
                    value={registerForm.name}
                    onChange={(e) => setRegisterForm({ ...registerForm, name: e.target.value })}
                    type="text"
                    placeholder="Your name"
                  />
                </div>

                <div className="field-block">
                  <label>Account type</label>
                  <div className="segmented segmented--compact">
                    <button type="button" className="segmented__button segmented__button--active">Customer</button>
                  </div>
                </div>

                <div className="field-block">
                  <label>Email address</label>
                  <input
                    value={registerForm.email}
                    onChange={(e) => setRegisterForm({ ...registerForm, email: e.target.value })}
                    type="email"
                    placeholder="you@example.com"
                  />
                </div>

                <div className="field-block">
                  <label>Password</label>
                  <input
                    value={registerForm.password}
                    onChange={(e) => setRegisterForm({ ...registerForm, password: e.target.value })}
                    type="password"
                    placeholder="Create a secure password"
                  />
                </div>

                <button type="submit" className="primary-btn w-full">Create account</button>

                <div className="auth-footer auth-footer--compact">
                  <div className="auth-switcher auth-switcher--footer">
                    <button type="button" className="auth-option auth-option--active">Customer</button>
                  </div>
                  <button type="button" className="text-link" onClick={() => setAuthMode('login')}>Back to sign in</button>
                </div>
              </form>
            )}
          </div>
        </div>
      );
    }

    switch (currentPage) {
      case 'Dashboard':
        return (
          <div className="page-stack">
            <div className="section-head">
              <div>
                <p className="section-kicker">Universal quantum security intelligence | SIMULATED DATA</p>
                <h2>ONE SECURITY ENGINE.<br />EVERY DIGITAL ENVIRONMENT.</h2>
              </div>
              <div className="section-actions">
                <button onClick={() => openCopilot('Dashboard', 'Summarize the current security posture, highest risks, and priority next steps.')} className="secondary-btn">Generate Llama briefing</button>
                {isAdmin && (
                  <button onClick={toggleMonitoring} className="secondary-btn">{liveMonitoring ? 'Pause live monitoring' : 'Start live monitoring'}</button>
                )}
              </div>
            </div>

            <div className="landing-hero glass-panel panel">
              <div className="landing-hero__content">
                <p className="section-kicker">ONE SECURITY INTELLIGENCE LAYER. EVERY PLATFORM.</p>
                <p className="landing-hero__meta">Universal quantum-inspired security intelligence for applications, endpoints, networks, cloud infrastructure, APIs, IoT and beyond.</p>
                <div className="landing-hero__actions">
                  <button className="primary-btn" onClick={() => setPage('Protected Environments')}>Protect an Environment</button>
                  <button className="secondary-btn" onClick={() => setPage('Quantum Security')}>Explore Security Architecture</button>
                </div>
              </div>
              <div className="landing-hero__visual">
                <div className="gateway-visual">
                  <div className="gateway-visual__core">QUANTUM + AI<br />SECURITY ENGINE</div>
                  <span className="gateway-visual__label gateway-visual__label--one">Windows</span>
                  <span className="gateway-visual__label gateway-visual__label--two">Linux</span>
                  <span className="gateway-visual__label gateway-visual__label--three">Cloud</span>
                  <span className="gateway-visual__label gateway-visual__label--four">Web</span>
                  <span className="gateway-visual__label gateway-visual__label--five">Mobile</span>
                </div>
              </div>
            </div>

            <div className="score-panel glass-panel panel">
              <div className="panel__head panel__head--spread">
                <div>
                  <p className="section-kicker">Global security overview</p>
                  <h3>GLOBAL SECURITY SCORE</h3>
                </div>
                <div className="score-overview">
                  <strong>92</strong>
                  <span>/ 100</span>
                </div>
              </div>
              <div className="score-grid">
                {[
                  ['Endpoint Security', 94],
                  ['Network Security', 91],
                  ['Application Security', 93],
                  ['Cloud Security', 89],
                  ['Identity Security', 95],
                  ['Data Security', 92],
                  ['Cryptographic Security', 90],
                  ['Threat Exposure', 86],
                ].map(([label, value]) => (
                  <div key={label} className="score-grid__item">
                    <span>{label}</span>
                    <strong>{value}</strong>
                    <div className="score-grid__bar"><i style={{ width: `${value}%` }} /></div>
                  </div>
                ))}
              </div>
            </div>

            <div className="stat-grid stat-grid--five">
              {[
                ['Threat Records', threats.length, 'Synthetic sample'],
                ['High / Critical', threats.filter((item) => ['high', 'critical'].includes(String(item.severity).toLowerCase())).length, 'Synthetic sample'],
                ['Active Incidents', incidentList.filter((item) => !['RESOLVED', 'CLOSED'].includes(String(item.status).toUpperCase())).length, 'Synthetic sample'],
                ['Verified Evidence', signatureState.valid ? 1 : 0, 'Local demo record'],
                ['Integrity Failures', signatureState.valid ? 0 : 1, 'Local demo record'],
              ].map(([label, value, trend]) => (
                <div key={label} className="glass-panel stat-card">
                  <div className="stat-card__top">
                    <span className="stat-label">{label}</span>
                    <span className="stat-trend">{trend}</span>
                  </div>
                  <div className="stat-card__value">{value}</div>
                </div>
              ))}
            </div>

            <div className="content-grid content-grid--wide">
              <div className="glass-panel panel">
                <div className="panel__head">
                  <div>
                    <h3>Live threat timeline</h3>
                    <span className="panel-caption">Latest detections and incident activity</span>
                  </div>
                  <span className={`badge border ${liveMonitoring ? statusColors.VALID : statusColors.default}`}>
                    {liveMonitoring ? 'MONITORING' : 'LATEST'}
                  </span>
                </div>
                <div className="activity-timeline">
                  {activityTimeline.length ? activityTimeline.map((item) => (
                    <div key={`${item.kind}-${item.id}`} className="activity-timeline__item">
                      <span className={`activity-timeline__marker activity-timeline__marker--${item.kind.toLowerCase()}`} />
                      <div className="activity-timeline__copy">
                        <strong>{item.title}</strong>
                        <span>{item.detail}</span>
                      </div>
                      <time>{item.timestamp ? new Date(item.timestamp).toLocaleString() : 'Time unavailable'}</time>
                    </div>
                  )) : <p className="empty-state">No threat or incident activity is available.</p>}
                </div>
              </div>

              <div className="glass-panel panel">
                <div className="panel__head">
                  <div>
                    <h3>Incident severity heatmap</h3>
                    <span className="panel-caption">Open workload by severity and response state</span>
                  </div>
                </div>
                <div className="severity-heatmap" role="table" aria-label="Incident counts by severity and status">
                  <div className="severity-heatmap__row severity-heatmap__row--header" role="row">
                    <span role="columnheader">Severity</span>
                    {incidentStatuses.map((status) => <span key={status} role="columnheader">{status}</span>)}
                  </div>
                  {severityLevels.map((severity) => (
                    <div key={severity} className="severity-heatmap__row" role="row">
                      <span className="severity-heatmap__label" role="rowheader">{severity}</span>
                      {incidentStatuses.map((status) => {
                        const count = incidentList.filter((incident) =>
                          String(incident.severity).toUpperCase() === severity &&
                          String(incident.status).toUpperCase() === status
                        ).length;
                        return (
                          <span
                            key={`${severity}-${status}`}
                            className={`severity-heatmap__cell severity-heatmap__cell--${severity.toLowerCase()}${count ? ' severity-heatmap__cell--active' : ''}`}
                            role="cell"
                            aria-label={`${count} ${severity.toLowerCase()} incidents ${status.toLowerCase()}`}
                          >
                            {count}
                          </span>
                        );
                      })}
                      </div>
                  ))}
                </div>
                <div className="heatmap-legend"><span>0</span><span>1+</span><span>More incidents</span></div>
              </div>
            </div>

            <div className="glass-panel panel response-playbook">
              <div className="panel__head">
                <div>
                  <h3>Recommended response playbook</h3>
                  <span className="panel-caption">{prioritizedThreat?.classification || 'Priority event'} · operational guidance</span>
                </div>
                {isAdmin && <button onClick={() => setPage('Incidents')} className="secondary-btn secondary-btn--small">Open incident queue</button>}
              </div>
              <div className="playbook-summary">
                <div>
                  <span>Why it matters</span>
                  <p>{activePlaybook.reason}</p>
                </div>
                <div>
                  <span>Recommended action</span>
                  <p>{activePlaybook.action}</p>
                </div>
              </div>
              <ol className="playbook-steps">
                {activePlaybook.steps.map((step, index) => (
                  <li key={`${index}-${step}`}><span>{index + 1}</span>{step}</li>
                ))}
              </ol>
            </div>

            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>{liveMonitoring ? 'Live threat feed' : 'Recent threats'}</h3>
                <button onClick={() => setPage('Threat Detection')} className="secondary-btn secondary-btn--small">Analyze event</button>
              </div>

              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Event ID</th>
                      <th>Threat</th>
                      <th>Source</th>
                      <th>Risk</th>
                      <th>Confidence</th>
                      <th>Status</th>
                      <th>Signature</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(liveThreats.length ? liveThreats : threats).map((item) => (
                      <tr key={item.id} onClick={() => setPage('Threat Detection')}>
                        <td className="event-id">{item.id}</td>
                        <td>{item.classification}{item.simulation && <span className="badge border simulation-feed-badge">SIMULATION</span>}</td>
                        <td>{item.source || item.source_ip || 'Unknown'}</td>
                        <td>{item.risk_score ?? item.risk}</td>
                        <td>{item.confidence ? `${item.confidence}%` : `${item.confidence_value ?? item.confidence ?? 'N/A'}`}</td>
                        <td><span className={`badge border ${statusColors[item.severity] || statusColors.default}`}>{item.severity || item.status}</span></td>
                        <td><span className={`badge border ${statusColors[item.status] || statusColors.default}`}>{item.status || 'ACTIVE'}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Protected Environments':
      case 'Security Sources':
        return (
          <div className="page-stack">
            <div className="section-head">
              <div>
                <p className="section-kicker">Universal protection layer</p>
                <h2>Protected Environments</h2>
              </div>
              <button className="primary-btn" onClick={() => setShowAddEnvironment(true)}>+ Add Protected Environment</button>
            </div>

            <div className="content-grid content-grid--analysis">
              <div className="glass-panel panel panel--tight">
                <div className="panel__head">
                  <h3>Connect Your Digital Environment</h3>
                </div>
                <p className="detector-note" style={{ marginTop: 0 }}>
                  One central security layer receives telemetry from websites, apps, endpoints, networks, containers, cloud infrastructure, APIs, databases, IoT, and enterprise systems, then applies the same AI and quantum-inspired protection model everywhere.
                </p>
              </div>

              <div className="glass-panel panel panel--tight">
                <div className="panel__head">
                  <h3>Universal Security Gateway</h3>
                </div>
                <div className="pipeline-list">
                  <div className="pipeline-item"><span className="pipeline-step">1</span> Collect from multiple platforms and agents</div>
                  <div className="pipeline-item"><span className="pipeline-step">2</span> Normalize into a common security event model</div>
                  <div className="pipeline-item"><span className="pipeline-step">3</span> Correlate threats across attack chains and systems</div>
                </div>
              </div>
            </div>

            <div className="environment-grid">
              {protectedEnvironments.map((environment) => (
                <div key={environment.id} className="glass-panel environment-card">
                  <div className="environment-card__header">
                    <span className="environment-card__name">{environment.name}</span>
                    <span className="environment-card__status">● {environment.status}</span>
                  </div>
                  <div className="environment-card__body">
                    <strong>{environment.type}</strong>
                    <span>Threats: {environment.threats}</span>
                  </div>
                  <div className="environment-card__footer">
                    <span>{environment.integration}</span>
                  </div>
                </div>
              ))}
            </div>

            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Protected environment telemetry</h3>
                <span>{protectedEnvironments.length} connected environments</span>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Environment</th><th>Platform</th><th>Threat count</th><th>Integration</th><th>Status</th></tr>
                  </thead>
                  <tbody>
                    {protectedEnvironments.map((environment) => (
                      <tr key={`${environment.id}-row`}>
                        <td>{environment.name}</td>
                        <td>{environment.type}</td>
                        <td>{environment.threats}</td>
                        <td>{environment.integration}</td>
                        <td><span className="badge border bg-emerald-500/15 text-emerald-300 border-emerald-500/50">Protected</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {showAddEnvironment && (
              <div className="environment-modal__backdrop" onClick={() => setShowAddEnvironment(false)}>
                <div className="environment-modal glass-panel" onClick={(event) => event.stopPropagation()}>
                  <div className="panel__head">
                    <div>
                      <p className="section-kicker">Environment onboarding</p>
                      <h3>WHAT DO YOU WANT TO PROTECT?</h3>
                    </div>
                    <button type="button" className="secondary-btn secondary-btn--small" onClick={() => setShowAddEnvironment(false)}>Close</button>
                  </div>
                  <div className="environment-modal__grid">
                    {environmentOptions.map((option) => (
                      <button
                        key={option.id}
                        type="button"
                        className={`environment-option ${selectedEnvironmentType === option.name ? 'environment-option--active' : ''}`}
                        onClick={() => {
                          setSelectedEnvironmentType(option.name);
                          addProtectedEnvironment(option.name);
                        }}
                      >
                        <span>{option.name}</span>
                        <small>{option.integration}</small>
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        );
      case 'Threat Detection':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Threat intelligence engine</p>
              <h2>Threat Detection</h2>
            </div>

            <div className="content-grid content-grid--analysis">
              <div className="glass-panel panel panel--tight">
                <div className="panel__head">
                  <h3>Quantum Threat Detection Workflow</h3>
                </div>

                <div className="detector-note">
                  <span>System state</span>
                  <p>{processingStatus}</p>
                </div>

                <div className="field-grid">
                  {[
                    ['Source IP', '203.0.113.27'],
                    ['Destination IP', '10.0.0.5'],
                    ['Protocol', 'TCP'],
                    ['Source Port', '52144'],
                    ['Destination Port', '80'],
                    ['Packet Count', '2400'],
                    ['Bytes Sent', '160000'],
                    ['Bytes Received', '50000'],
                    ['Connection Duration', '120'],
                    ['Failed Login Attempts', '12'],
                    ['Request Frequency', '68'],
                  ].map(([label, value]) => (
                    <div key={label} className="field-block field-block--compact">
                      <label>{label}</label>
                      <input defaultValue={value} />
                    </div>
                  ))}
                </div>

                <button onClick={analyzeThreat} className="primary-btn" disabled={isProcessing}>
                  {isProcessing ? 'Processing...' : 'Run Quantum Detection'}
                </button>
              </div>

              <div className="glass-panel panel panel--tight">
                <div className="panel__head">
                  <h3>Processing pipeline</h3>
                </div>
                <div className="pipeline-list">
                  {['Event Validation', 'Platform Normalization', 'Feature Extraction', 'Rule-Based Detection', 'Operational Risk', 'Ed25519 Evidence Signing'].map((step, idx) => (
                    <div key={step} className={`pipeline-item ${processingStatus.includes(step) || (idx === 0 && !threatResult) ? 'pipeline-item--active' : ''}`}>
                      <span className="pipeline-step">{idx + 1}</span>
                      <span>{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {threatResult && (
              <div className="glass-panel panel panel--alert">
                <div className="panel__head panel__head--spread">
                  <h3 className="panel__title">Threat detected</h3>
                  {isAdmin && (
                    <button onClick={createIncident} className="secondary-btn secondary-btn--small">Create incident</button>
                  )}
                </div>

                <div className="result-grid">
                  <div><span>Classification</span><strong>{threatResult.classification}</strong></div>
                  <div><span>Risk Score</span><strong>{threatResult.risk_score} / 100</strong></div>
                  <div><span>Rule Signal Strength</span><strong>{threatResult.confidence}%</strong></div>
                  <div><span>Severity</span><strong className="text-danger">{threatResult.severity}</strong></div>
                </div>

                <div className="content-grid content-grid--analysis" style={{ marginTop: 18 }}>
                  <div className="glass-panel panel panel--tight" style={{ background: 'rgba(15, 23, 42, 0.6)' }}>
                    <div className="panel__head"><h3>Why this is happening</h3></div>
                    <div className="detector-note">
                      <p>{threatResult.reason || 'The system detected a signal above the configured security threshold.'}</p>
                    </div>
                    <div className="detector-note">
                      <span>Evidence</span>
                      <ul style={{ margin: '10px 0 0', paddingLeft: 18, color: '#dbeafe' }}>
                        {(threatResult.explanations || []).map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>

                  <div className="glass-panel panel panel--tight" style={{ background: 'rgba(15, 23, 42, 0.6)' }}>
                    <div className="panel__head"><h3>Recommended solution</h3></div>
                    <div className="detector-note">
                      <span>Action plan</span>
                      <p>{threatResult.recommended_action || 'Apply the relevant protection controls and verify the affected assets.'}</p>
                    </div>
                    <div className="detector-note">
                      <span>Response steps</span>
                      <ul style={{ margin: '10px 0 0', paddingLeft: 18, color: '#dbeafe' }}>
                        {(threatResult.remediation_steps || []).map((step) => (
                          <li key={step}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                <div className="detector-note">
                  <span>Detection Method</span>
                  <p>{threatResult.detection_method}</p>
                </div>
                <div className="detector-note">
                  <span>Analysis provider</span>
                  <p>{threatResult.analysis_provider || 'Rule-based Detection'}{threatResult.ai_enhanced ? ' · Llama explanations active' : ''}</p>
                </div>
              </div>
            )}
          </div>
        );
      case 'Quantum Optimization':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Model tuning</p>
              <h2>Quantum-Inspired Optimization</h2>
            </div>

            <div className="stat-grid stat-grid--three">
              {[
                ['Candidate Features', '11'],
                ['Selected Features', '7'],
                ['Feature Reduction', '36%'],
              ].map(([label, value]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                </div>
              ))}
            </div>

            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Optimization pipeline</h3>
              </div>
              <div className="pipeline-list">
                {['Input Features', 'Quantum-Inspired Search', 'Candidate Feature Sets', 'Fitness Evaluation', 'Optimal Feature Set'].map((step, idx) => (
                  <div key={step} className="pipeline-item">
                    <span className="pipeline-step">{idx + 1}</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Model performance</h3>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Baseline</th>
                      <th>Optimized</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td colSpan="3">No model benchmark has been run. Comparative performance is not measured.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Incidents':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Case management</p>
              <h2>Incidents</h2>
            </div>
            <div className="glass-panel panel">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Incident ID</th>
                      <th>Threat Type</th>
                      <th>Severity</th>
                      <th>Source</th>
                      <th>Detected At</th>
                      <th>Risk Score</th>
                      <th>Confidence</th>
                      <th>Status</th>
                      <th>Assigned Analyst</th>
                      {isAdmin && <th>Response actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {incidentList.map((incident) => (
                      <tr key={incident.id}>
                        <td>{incident.id}</td>
                        <td>{incident.threatType}</td>
                        <td>{incident.severity}</td>
                        <td>{incident.source}</td>
                        <td>{incident.detectedAt}</td>
                        <td>{incident.riskScore}</td>
                        <td>{incident.confidence}%</td>
                        <td><span className={`badge border ${statusColors[incident.status] || statusColors.default}`}>{incident.status}</span></td>
                        <td>{incident.assignedAnalyst}</td>
                        {isAdmin && (
                          <td>
                            <div className="incident-actions">
                              <button
                                type="button"
                                className="secondary-btn secondary-btn--small"
                                disabled={updatingIncidentId === incident.id}
                                onClick={() => updateIncident(incident, { status: 'INVESTIGATING' }, 'Incident moved to investigation')}
                              >
                                Investigate
                              </button>
                              <button
                                type="button"
                                className="secondary-btn secondary-btn--small"
                                disabled={updatingIncidentId === incident.id}
                                onClick={() => updateIncident(incident, { status: 'CONTAINED' }, 'Incident contained')}
                              >
                                Contain
                              </button>
                              <button
                                type="button"
                                className="secondary-btn secondary-btn--small"
                                disabled={updatingIncidentId === incident.id}
                                onClick={() => updateIncident(incident, { status: 'RESOLVED' }, 'Incident resolved')}
                              >
                                Resolve
                              </button>
                              <button
                                type="button"
                                className="secondary-btn secondary-btn--small secondary-btn--danger"
                                disabled={updatingIncidentId === incident.id}
                                onClick={() => {
                                  const nextLevel = incident.escalation_level === 'L2' ? 'SOC_MANAGER' : 'L2';
                                  updateIncident(
                                    incident,
                                    { escalated: true, escalation_level: nextLevel },
                                    `Incident escalated to ${nextLevel === 'L2' ? 'L2' : 'SOC manager'}`
                                  );
                                }}
                              >
                                {incident.escalation_level === 'L2' ? 'Escalate to SOC manager' : 'Escalate to L2'}
                              </button>
                              {updatingIncidentId === incident.id && <span className="incident-actions__pending">Updating...</span>}
                            </div>
                          </td>
                        )}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Signature Verification':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Integrity proof</p>
              <h2>Digital Signature Verification</h2>
            </div>
            <div className="glass-panel panel panel--wide">
              <div className="verification-copy">Security Event → Canonical Data → SHA-256 Hash → Digital Signature → Secure Event Record</div>
              <div className="verification-grid">
                <div>
                  <span>Event ID</span>
                  <strong>{signatureState.eventId}</strong>
                </div>
                <div>
                  <span>Signed at</span>
                  <strong>{signatureState.signedAt}</strong>
                </div>
                <div>
                  <span>Signing key mode</span>
                  <strong>{signatureState.keyMode}</strong>
                </div>
                <div>
                  <span>Verification result</span>
                  <strong className={signatureState.valid ? 'text-success' : 'text-danger'}>{signatureState.status}</strong>
                </div>
                <div className="verification-grid__full">
                  <span>Hash</span>
                  <code>{signatureState.hash}</code>
                </div>
                <div className="verification-grid__full">
                  <span>Digital Signature</span>
                  <code>{signatureState.signature}</code>
                </div>
              </div>
              <div className="verification-actions">
                <button onClick={verifyThreat} disabled={!threatResult || signatureState.signature === 'Not signed'} className="primary-btn primary-btn--success">Verify signature</button>
                <button onClick={tamperThreat} disabled={!threatResult || signatureState.signature === 'Not signed'} className="secondary-btn secondary-btn--danger">Simulate tampering</button>
              </div>
            </div>
          </div>
        );
      case 'AI Security Copilot':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Context-aware security analysis</p>
              <h2>AI Security Copilot</h2>
            </div>

            <div className="stat-grid stat-grid--three">
              {[
                ['Provider', aiStatus?.provider || 'Ollama · Llama 3.2'],
                ['Configuration', aiStatus ? (aiStatus.configured ? 'Ready' : aiStatus.status === 'model_not_found' ? 'Model missing' : 'Ollama offline') : 'Checking'],
                ['Model', aiStatus?.model || 'llama3.2:3B'],
              ].map(([label, value]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value copilot-stat-value">{value}</div>
                </div>
              ))}
            </div>

            <div className="glass-panel panel copilot-panel">
              <form onSubmit={submitCopilotQuestion}>
                <div className="copilot-form-row">
                  <label className="field-block">
                    <span>Security area</span>
                    <select className="copilot-scope" value={copilotScope} onChange={(event) => setCopilotScope(event.target.value)}>
                      {navItems.filter((item) => item !== 'AI Security Copilot').map((item) => <option key={item} value={item}>{item}</option>)}
                    </select>
                  </label>
                  <label className="field-block copilot-question-field">
                    <span>Ask a security question</span>
                    <textarea
                      value={copilotQuestion}
                      onChange={(event) => setCopilotQuestion(event.target.value)}
                      maxLength={1200}
                      placeholder="Ask about current threats, risk drivers, response options, or integration health"
                      rows={3}
                    />
                  </label>
                </div>
                <div className="copilot-actions">
                  <button className="primary-btn" type="submit" disabled={isCopilotLoading || copilotQuestion.trim().length < 3}>
                    {isCopilotLoading ? 'Analyzing...' : 'Ask Llama'}
                  </button>
                  {!aiStatus?.configured && <span className="copilot-config-hint">Start Ollama and run ollama pull llama3.2:3B to enable the copilot.</span>}
                </div>
              </form>

              <div className="copilot-quick-prompts">
                {[
                  'What are the top risks in this security area?',
                  'Recommend the next defensive response steps.',
                  'Summarize the current telemetry and evidence gaps.',
                ].map((prompt) => (
                  <button key={prompt} type="button" className="secondary-btn secondary-btn--small" onClick={() => { setCopilotQuestion(prompt); askCopilot(prompt); }}>
                    {prompt}
                  </button>
                ))}
              </div>

              {copilotAnswer && (
                <div className="copilot-answer" role="status">
                  <div className="panel__head">
                    <h3>Security analysis</h3>
                    <span className="badge border">{copilotAnswer.provider}</span>
                  </div>
                  <p>{copilotAnswer.answer}</p>
                </div>
              )}
            </div>
          </div>
        );
      case 'Audit Logs':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Event trail</p>
              <h2>Audit Logs</h2>
            </div>
            <div className="glass-panel panel">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>User</th>
                      <th>Action</th>
                      <th>Resource</th>
                      <th>Event ID</th>
                      <th>Signature Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((entry, idx) => (
                      <tr key={idx}>
                        <td>{entry.timestamp}</td>
                        <td>{entry.user}</td>
                        <td>{entry.action}</td>
                        <td>{entry.resource}</td>
                        <td>{entry.eventId}</td>
                        <td><span className={`badge border ${statusColors[entry.signatureStatus] || statusColors.default}`}>{entry.signatureStatus}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'AI Analytics':
      case 'Analytics':
        return (
          <div className="page-stack">
            <div className="section-head">
              <div>
                <p className="section-kicker">Detection intelligence · rolling five-day window</p>
                <h2>AI Analytics</h2>
              </div>
              <div className="section-actions">
                <span className={`badge border ${analyticsData?.event_count ? statusColors.VALID : statusColors.default}`}>
                  {analyticsData?.data_mode === 'simulation' ? 'LIVE SIMULATION' : analyticsData?.data_mode === 'live' ? 'LIVE EVENTS' : 'AWAITING EVENTS'}
                </span>
                <button className="primary-btn" type="button" onClick={() => openCopilot('AI Analytics', 'Analyze the five-day threat analytics. Explain the main severity trends, risk level, and defensive priorities using the supplied data.')}>Generate AI insight</button>
              </div>
            </div>

            {analyticsError && <div className="detector-note"><span>Analytics feed</span><p>{analyticsError}</p></div>}

            <div className="stat-grid stat-grid--four">
              {[
                ['Observed detections', analyticsData?.event_count ?? 0, 'Recorded in last 5 days'],
                ['Average risk', `${analyticsData?.average_risk ?? 0}/100`, 'From recorded event scores'],
                ['Critical events', analyticsData?.critical_count ?? 0, 'Current 5-day window'],
                ['Llama enriched', analyticsData?.ai_enriched_count ?? 0, 'AI explanations attached'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>

            <div className="content-grid content-grid--analytics">
              <div className="glass-panel panel analytics-chart-panel">
                <div className="panel__head">
                  <div>
                    <h3>Threats over time</h3>
                    <span className="panel-caption">Daily totals include live detections · refreshes every 2 seconds</span>
                  </div>
                </div>
                {analyticsBuckets.some((bucket) => bucket.total > 0) ? (
                  <div className="threat-trend-chart" role="img" aria-label="Stacked daily detection counts by severity over five days">
                    {analyticsBuckets.map((bucket) => (
                      <div key={bucket.time} className="threat-trend-column" title={`${bucket.time}: ${bucket.total} events`}>
                        <div className="threat-trend-track">
                          <div className="threat-trend-stack" style={{ height: `${bucket.total / analyticsBucketMax * 100}%` }}>
                            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map((severity) => (
                              bucket[severity] > 0 && <span key={severity} style={{ height: `${bucket[severity] / bucket.total * 100}%`, backgroundColor: severityColors[severity] }} />
                            ))}
                          </div>
                        </div>
                        <time>{bucket.time}</time>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="analytics-empty">No analyzed or ingested events in the last five days. New detections will appear here automatically.</div>
                )}
                <div className="analytics-legend">
                  {Object.entries(severityColors).map(([severity, color]) => (
                    <span key={severity}><i style={{ backgroundColor: color }} />{severity}</span>
                  ))}
                </div>
              </div>

              <div className="glass-panel panel analytics-chart-panel">
                <div className="panel__head">
                  <div>
                    <h3>Severity distribution</h3>
                    <span className="panel-caption">{analyticsSeverityTotal} recorded detections</span>
                  </div>
                </div>
                <div className="severity-distribution">
                  <div className="severity-donut" style={{ background: analyticsPieBackground }} role="img" aria-label={`Severity distribution across ${analyticsSeverityTotal} events`}>
                    <div><strong>{analyticsSeverityTotal}</strong><span>events</span></div>
                  </div>
                  <div className="severity-legend">
                    {analyticsSeverityEntries.length ? analyticsSeverityEntries.map(([severity, count]) => (
                      <div key={severity}>
                        <span><i style={{ backgroundColor: severityColors[severity] || severityColors.UNKNOWN }} />{severity}</span>
                        <strong>{count} <small>{analyticsSeverityTotal ? `${Math.round(count / analyticsSeverityTotal * 100)}%` : '0%'}</small></strong>
                      </div>
                    )) : <p className="analytics-empty">No severity data yet.</p>}
                  </div>
                </div>
              </div>
            </div>

            <div className="analytics-footnote">
              History is retained for five days. Live detections and SIMULATION events are counted separately; demo feed samples are excluded. Last refresh: {analyticsData?.updated_at ? new Date(analyticsData.updated_at).toLocaleTimeString() : 'Waiting for API'}.
            </div>
          </div>
        );
      case 'Threat Simulation Lab': {
        const selectedScenario = simulationScenarios.find((item) => item.id === simulationConfig.scenario_id);
        const simulationMetrics = activeSimulation?.metrics || {};
        const simulationProgress = activeSimulation
          ? Math.min(100, Math.round(activeSimulation.events_generated / Math.max(1, activeSimulation.config?.event_volume || simulationConfig.event_volume) * 100))
          : 0;
        const scenarioCategories = [...new Set(simulationScenarios.map((item) => item.category))];

        return (
          <div className="page-stack simulation-lab">
            <div className="section-head">
              <div>
                <p className="section-kicker">Cyber threat simulation lab</p>
                <h2>CYBER THREAT SIMULATION LAB</h2>
                <p className="simulation-subtitle">Generate controlled synthetic incidents to evaluate detection capabilities.</p>
              </div>
              <div className="simulation-status-pill"><span />SANDBOX MODE</div>
            </div>

            <div className="simulation-safety-banner">
              <strong>SIMULATION MODE · DEMO / ISOLATED</strong>
              <span>Synthetic telemetry only. No real systems, accounts, network traffic, malware, or destructive commands are used.</span>
            </div>

            {!isAdmin && <div className="detector-note"><span>Administrator access required</span><p>Simulation runs and custom scenarios are restricted to administrators. This account can view other security modules.</p></div>}
            {simulationError && <div className="detector-note simulation-error"><span>Simulation error</span><p>{simulationError}</p></div>}

            <div className="stat-grid stat-grid--five simulation-stat-grid">
              {[
                ['Events Generated', activeSimulation?.events_generated ?? 0],
                ['Threats Detected', activeSimulation?.threats_detected ?? 0],
                ['Incidents Created', activeSimulation?.metrics?.incidents_created ?? 0],
                ['Detection Accuracy', activeSimulation?.metrics?.detection_rate != null ? `${activeSimulation.metrics.detection_rate}%` : 'N/A'],
                ['Environment', 'DEMO / ISOLATED'],
              ].map(([label, value]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value simulation-stat-value">{value}</div>
                </div>
              ))}
            </div>

            <div className="simulation-lab-grid">
              <section className="glass-panel panel">
                <div className="panel__head"><div><h3>Attack scenario library</h3><span className="panel-caption">Select a controlled scenario to configure</span></div></div>
                <div className="scenario-library">
                  {scenarioCategories.map((category) => {
                    const items = simulationScenarios.filter((item) => item.category === category);
                    return (
                      <details key={category} open={category === 'UNIVERSAL'}>
                        <summary>{category}<span>{items.length} scenarios</span></summary>
                        <div className="scenario-library-grid">
                          {items.map((item) => (
                            <button
                              type="button"
                              key={item.id}
                              className={`scenario-option${simulationConfig.scenario_id === item.id ? ' scenario-option--active' : ''}`}
                              onClick={() => setSimulationConfig((current) => ({ ...current, scenario_id: item.id, target_platform: item.category === 'UNIVERSAL' ? 'linux' : current.target_platform }))}
                            >
                              <span>{item.name}</span>
                              {item.custom && <small>CUSTOM</small>}
                            </button>
                          ))}
                        </div>
                      </details>
                    );
                  })}
                  {!simulationScenarios.length && <p className="analytics-empty">Loading scenario catalog…</p>}
                </div>
              </section>

              <section className="glass-panel panel">
                <div className="panel__head"><div><h3>Simulation configuration</h3><span className="panel-caption">All identities, hosts, and addresses are synthetic</span></div></div>
                <div className="simulation-selected-scenario">{selectedScenario?.name || 'Choose a scenario'}<small>{selectedScenario?.category || 'SCENARIO'}</small></div>
                <div className="simulation-config-grid">
                  <label className="field-block"><span>Attack type</span><input value={selectedScenario?.name || ''} readOnly /></label>
                  <label className="field-block"><span>Target environment</span><select value={simulationConfig.target_platform} onChange={(event) => setSimulationConfig((current) => ({ ...current, target_platform: event.target.value }))}>{['web', 'api', 'cloud', 'linux', 'database', 'identity', 'network', 'endpoint'].map((platform) => <option key={platform} value={platform}>{platform.toUpperCase()}</option>)}</select></label>
                  <label className="field-block"><span>Severity</span><select value={simulationConfig.severity} onChange={(event) => setSimulationConfig((current) => ({ ...current, severity: event.target.value }))}>{['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].map((level) => <option key={level}>{level}</option>)}</select></label>
                  <label className="field-block"><span>Event volume</span><input type="number" min="1" max="250" value={simulationConfig.event_volume} onChange={(event) => setSimulationConfig((current) => ({ ...current, event_volume: Math.max(1, Math.min(250, Number(event.target.value) || 1)) }))} /></label>
                  <label className="field-block"><span>Simulation duration (sec)</span><input type="number" min="5" max="120" value={simulationConfig.duration_seconds} onChange={(event) => setSimulationConfig((current) => ({ ...current, duration_seconds: Math.max(5, Math.min(120, Number(event.target.value) || 5)) }))} /></label>
                  <label className="field-block"><span>Attacker identity</span><input value={simulationConfig.attacker_identity} onChange={(event) => setSimulationConfig((current) => ({ ...current, attacker_identity: event.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '').startsWith('demo_') ? event.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '') : `demo_${event.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24)}` }))} /></label>
                  <label className="field-block"><span>Target identity</span><input value={simulationConfig.target_identity} onChange={(event) => setSimulationConfig((current) => ({ ...current, target_identity: event.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '').startsWith('demo_') ? event.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '') : `demo_${event.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24)}` }))} /></label>
                  <label className="field-block"><span>Protocol</span><select value={simulationConfig.protocol} onChange={(event) => setSimulationConfig((current) => ({ ...current, protocol: event.target.value }))}>{['TCP', 'UDP', 'HTTPS', 'DNS'].map((protocol) => <option key={protocol}>{protocol}</option>)}</select></label>
                  <label className="field-block"><span>Timestamp pattern</span><select value={simulationConfig.timestamp_pattern} onChange={(event) => setSimulationConfig((current) => ({ ...current, timestamp_pattern: event.target.value }))}>{['SEQUENTIAL', 'BURST', 'SLOW_DRIP', 'IRREGULAR'].map((pattern) => <option key={pattern} value={pattern}>{pattern.replaceAll('_', ' ')}</option>)}</select></label>
                  <label className="field-block"><span>Detection difficulty</span><select value={simulationConfig.difficulty} onChange={(event) => setSimulationConfig((current) => ({ ...current, difficulty: event.target.value }))}>{['EASY', 'MEDIUM', 'HARD', 'ADVERSARIAL', 'UNKNOWN'].map((level) => <option key={level}>{level}</option>)}</select></label>
                  <div className="field-block"><span>Synthetic source</span><strong className="simulation-safe-value">198.51.100.42 · 203.0.113.29 · 192.0.2.18</strong></div>
                  <div className="field-block"><span>Synthetic destination</span><strong className="simulation-safe-value">demo-*.test</strong></div>
                </div>
                <div className="simulation-run-actions">
                  <button type="button" className="primary-btn" disabled={!isAdmin || isStartingSimulation || activeSimulation?.status === 'running' || !selectedScenario} onClick={() => startSimulation()}>{isStartingSimulation ? 'Preparing sandbox…' : 'Run selected simulation'}</button>
                  <button type="button" className="secondary-btn" disabled={!isAdmin || isStartingSimulation || activeSimulation?.status === 'running'} onClick={() => startSimulation('universal-cross-platform', { event_volume: 47, duration_seconds: 60, target_platform: 'linux', difficulty: 'MEDIUM' })}>Run full cyber attack simulation</button>
                </div>
              </section>
            </div>

            <details className="glass-panel panel custom-scenario-builder">
              <summary>Custom scenario builder <span>Admin only · synthetic event templates</span></summary>
              <div className="simulation-config-grid custom-scenario-grid">
                <label className="field-block"><span>Scenario name</span><input value={customScenarioName} maxLength={80} onChange={(event) => setCustomScenarioName(event.target.value)} placeholder="Demo credential-to-data chain" /></label>
                <label className="field-block"><span>Attack category</span><select value={customScenarioCategory} onChange={(event) => setCustomScenarioCategory(event.target.value)}>{['NETWORK', 'WEB / APPLICATION', 'IDENTITY', 'ENDPOINT', 'CLOUD', 'DATA', 'AI SECURITY', 'CRYPTOGRAPHIC / QUANTUM'].map((category) => <option key={category}>{category}</option>)}</select></label>
                <label className="field-block"><span>Target platform</span><select value={customScenarioPlatform} onChange={(event) => setCustomScenarioPlatform(event.target.value)}>{['web', 'api', 'cloud', 'linux', 'database', 'identity', 'network', 'endpoint'].map((platform) => <option key={platform}>{platform}</option>)}</select></label>
                <label className="field-block"><span>Noise level</span><select value={customScenarioNoise} onChange={(event) => setCustomScenarioNoise(event.target.value)}>{['LOW', 'MEDIUM', 'HIGH'].map((level) => <option key={level}>{level}</option>)}</select></label>
                <label className="field-block"><span>Expected detection</span><input value={customExpectedDetection} onChange={(event) => setCustomExpectedDetection(event.target.value)} maxLength={240} /></label>
                <label className="field-block"><span>Expected MITRE mapping</span><input value={customExpectedMitre} onChange={(event) => setCustomExpectedMitre(event.target.value)} maxLength={120} /></label>
                <label className="field-block"><span>Expected response</span><input value={customExpectedResponse} onChange={(event) => setCustomExpectedResponse(event.target.value)} maxLength={240} /></label>
                <label className="field-block"><span>Add event stage</span><div className="custom-stage-control"><select value={customScenarioStage} onChange={(event) => setCustomScenarioStage(event.target.value)}>{['port_scan', 'authentication_failure', 'credential_stuffing', 'privilege_escalation', 'lateral_movement', 'database_access_anomaly', 'data_exfiltration', 'routine_activity', 'sql_injection_attempt', 'api_abuse', 'dns_anomaly', 'suspicious_process', 'iam_anomaly'].map((stage) => <option key={stage}>{stage}</option>)}</select><button type="button" className="secondary-btn secondary-btn--small" disabled={customScenarioSequence.length >= 8} onClick={() => setCustomScenarioSequence((current) => [...current, customScenarioStage])}>Add stage</button></div></label>
              </div>
              <div className="custom-sequence-list">{customScenarioSequence.map((stage, index) => <span key={`${stage}-${index}`}><b>{index + 1}</b>{stage.replaceAll('_', ' ')}<button type="button" aria-label={`Remove ${stage}`} onClick={() => setCustomScenarioSequence((current) => current.filter((_, itemIndex) => itemIndex !== index))}>×</button></span>)}</div>
              <button type="button" className="primary-btn" disabled={!isAdmin || !customScenarioName.trim() || !customScenarioSequence.length} onClick={createCustomScenario}>Save custom scenario</button>
            </details>

            {activeSimulation && (
              <div className="page-stack simulation-results">
                <section className="glass-panel panel">
                  <div className="panel__head panel__head--spread">
                    <div><p className="section-kicker">SIMULATION · {activeSimulation.id}</p><h3>{activeSimulation.config?.scenario_name || selectedScenario?.name}</h3><span className="panel-caption">{activeSimulation.status.toUpperCase()} · DEMO / ISOLATED</span></div>
                    <span className={`badge border ${activeSimulation.status === 'completed' ? statusColors.VALID : statusColors.default}`}>{activeSimulation.status === 'completed' ? 'SIMULATION COMPLETE' : 'RUNNING'}</span>
                  </div>
                  <div className="simulation-progress"><span style={{ width: `${simulationProgress}%` }} /></div>
                  <div className="simulation-progress-label">{activeSimulation.events_generated} / {activeSimulation.config?.event_volume || simulationConfig.event_volume} synthetic events processed</div>
                  <div className="simulation-live-grid">
                    <div><span>Detection rate</span><strong>{simulationMetrics.detection_rate != null ? `${simulationMetrics.detection_rate}%` : 'Calculating'}</strong></div>
                    <div><span>False-positive rate</span><strong>{simulationMetrics.false_positive_rate != null ? `${simulationMetrics.false_positive_rate}%` : 'Calculating'}</strong></div>
                    <div><span>Detection latency</span><strong>{simulationMetrics.detection_latency_ms != null ? `${simulationMetrics.detection_latency_ms} ms` : 'Calculating'}</strong></div>
                    <div><span>Quantum-inspired score</span><strong>{simulationMetrics.quantum_inspired_score != null ? `${simulationMetrics.quantum_inspired_score}%` : 'Calculating'}</strong></div>
                  </div>
                </section>

                <div className="simulation-results-grid">
                  <section className="glass-panel panel">
                    <div className="panel__head"><div><h3>Unified attack graph</h3><span className="panel-caption">Click a detected stage to inspect its synthetic event</span></div><span className="badge border">QUANTUM-INSPIRED SIMULATION</span></div>
                    {activeSimulation.attack_graph?.length ? <div className="simulation-attack-graph">{activeSimulation.attack_graph.map((node, index) => (
                      <Fragment key={node.id}>
                        <button type="button" className="attack-graph-node" onClick={() => setSelectedSimulationEvent(activeSimulation.events.find((event) => event.id === node.id))}>
                          <span className="attack-node-number">{index + 1}</span><strong>{node.event}</strong><small>{node.stage} · {node.platform}</small><span>Risk {node.risk} · {node.confidence}% confidence</span><time>{new Date(node.timestamp).toLocaleTimeString()}</time>
                        </button>
                        {index < activeSimulation.attack_graph.length - 1 && <span className="attack-graph-connector" aria-hidden="true">→</span>}
                      </Fragment>
                    ))}</div> : <div className="analytics-empty">Attack path nodes appear as the shared detector identifies related stages.</div>}
                    {selectedSimulationEvent && <div className="simulation-event-inspector"><div className="panel__head"><h3>{selectedSimulationEvent.simulation_stage}</h3><button type="button" className="secondary-btn secondary-btn--small" onClick={() => setSelectedSimulationEvent(null)}>Close</button></div><p>{selectedSimulationEvent.reason}</p><strong>{selectedSimulationEvent.classification || selectedSimulationEvent.threat_type} · {selectedSimulationEvent.severity} · {selectedSimulationEvent.risk_score}/100</strong><pre>{JSON.stringify(selectedSimulationEvent.raw_event, null, 2)}</pre></div>}
                  </section>

                  <section className="glass-panel panel">
                    <div className="panel__head"><div><h3>Live synthetic event stream</h3><span className="panel-caption">Updates while the isolated scenario runs</span></div><span className="simulation-live-dot">● SIMULATION</span></div>
                    <div className="simulation-event-stream" aria-live="polite">
                      {(activeSimulation.event_stream || []).slice(-16).reverse().map((event, index) => <div className="simulation-feed-item" key={`${event.timestamp}-${index}`}><time>{new Date(event.timestamp).toLocaleTimeString()}</time><strong>{event.event_type}</strong><span>{event.source_platform || event.stage}</span><b>{event.result}</b></div>)}
                      {!activeSimulation.event_stream?.length && <p className="analytics-empty">Waiting for generated events…</p>}
                    </div>
                  </section>
                </div>

                {activeSimulation.correlation?.triggered && <section className="glass-panel panel simulation-incident-panel">
                  <div className="panel__head"><div><p className="section-kicker">CORRELATED INCIDENT · SIMULATION</p><h3>{activeSimulation.incident?.id} · {activeSimulation.incident?.threat_type}</h3></div><span className="badge border">{activeSimulation.incident?.severity}</span></div>
                  <p>{activeSimulation.correlation.reason}</p>
                  <div className="simulation-incident-summary"><span>Status<strong>{activeSimulation.incident?.status}</strong></span><span>Risk<strong>{activeSimulation.incident?.risk_score}/100</strong></span><span>Evidence<strong>{activeSimulation.incident?.evidence_count} correlated stages</strong></span><span>Assets<strong>{activeSimulation.attack_graph?.map((node) => node.platform).filter((value, index, all) => all.indexOf(value) === index).join(', ')}</strong></span></div>
                  <div className="simulation-mitre-list"><strong>MITRE ATT&CK mapping</strong>{activeSimulation.incident?.mitre_mapping?.map((item) => <span key={item.id} className="badge border">{item.id} · {item.name}</span>)}</div>
                  <div className="simulation-response-actions">{[
                    ['SIMULATE_ACCOUNT_LOCK', 'Simulate account lock'],
                    ['SIMULATE_ENDPOINT_ISOLATION', 'Simulate endpoint isolation'],
                    ['SIMULATE_IP_BLOCK', 'Simulate IP block'],
                    ['SIMULATE_SESSION_REVOCATION', 'Simulate session revocation'],
                    ['SIMULATE_CREDENTIAL_ROTATION', 'Simulate credential rotation'],
                    ['SIMULATE_INCIDENT_ESCALATION', 'Simulate incident escalation'],
                  ].map(([action, label]) => <button key={action} type="button" className="secondary-btn secondary-btn--small" disabled={activeSimulation.status !== 'completed'} onClick={() => simulateResponseAction(action)}>{label}</button>)}</div>
                  {simulationActionResult && <div className="simulation-response-result"><strong>SIMULATED RESPONSE EXECUTED</strong><span>{simulationActionResult.action.replaceAll('_', ' ')}</span><span>Target: {simulationActionResult.target}</span><b>{simulationActionResult.result}</b></div>}
                  {activeSimulation.ai_analysis && <div className="detector-note"><span>Llama AI analysis · synthetic data</span><p>{activeSimulation.ai_analysis.answer}</p></div>}
                </section>}
              </div>
            )}
          </div>
        );
      }
      case 'Attack Intelligence':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Cross-platform correlation</p>
              <h2>Attack Intelligence</h2>
            </div>

            <div className="stat-grid stat-grid--four">
              {[
                ['Correlated events', activityTimeline.length, 'Across all platforms'],
                ['Critical paths', securityMetrics.criticalThreats || 1, 'Linked to escalations'],
                ['Attack chain focus', threatResult ? 'Privilege escalation' : 'Authentication abuse', 'Most likely path'],
                ['Confidence', threatResult ? `${threatResult.confidence}%` : '94%', 'Model confidence'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>

            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Attack Chain Visualization</h3>
              </div>
              <div className="pipeline-list">
                {['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Lateral Movement', 'Data Access', 'Possible Exfiltration'].map((step, index) => (
                  <div key={step} className="pipeline-item">
                    <span className="pipeline-step">{index + 1}</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Active correlation findings</h3>
              </div>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr><th>Event</th><th>Source</th><th>Platform</th><th>Stage</th><th>Outcome</th></tr>
                  </thead>
                  <tbody>
                    {(timelineThreats.slice(0, 4)).map((item, index) => (
                      <tr key={`${item.id || index}-correlation`}>
                        <td>{item.classification || 'Authentication anomaly'}</td>
                        <td>{item.source || item.source_ip || 'Internal'}</td>
                        <td>{index === 0 ? 'Linux Server' : index === 1 ? 'Cloud' : index === 2 ? 'Web Application' : 'Windows'}</td>
                        <td>{index === 3 ? 'Credential abuse' : 'Privilege escalation'}</td>
                        <td>{Number(item.risk_score ?? item.risk ?? 0) >= 80 ? 'Escalated' : 'Monitored'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Quantum Security':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Quantum-inspired analytics</p>
              <h2>Quantum Security</h2>
            </div>
            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Quantum Security Engine</h3>
              </div>
              <div className="pipeline-list">
                {['Security Data', 'Quantum-Inspired Engine', 'Threat Probability / Risk Score', 'Detection Result'].map((step, index) => (
                  <div key={step} className="pipeline-item">
                    <span className="pipeline-step">{index + 1}</span>
                    <span>{step}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );
      case 'Network Security':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Threat surface control</p>
              <h2>Network Security</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Blocked sources', Math.max(4, securityMetrics.highRiskSignals), 'Traffic filtering'],
                ['Malformed requests', Math.max(8, Math.round(securityMetrics.avgRisk / 6)), 'Edge protection'],
                ['Suspicious flows', securityMetrics.criticalThreats || 2, 'Intra-network activity'],
                ['Outcome', 'Quarantined', 'Monitoring status'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Network detections</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Source</th><th>Protocol</th><th>Severity</th><th>Risk</th><th>Outcome</th></tr></thead>
                  <tbody>
                    {(timelineThreats.slice(0, 5)).map((item, idx) => (
                      <tr key={`${item.id || idx}-network`}>
                        <td>{item.source || item.source_ip || '192.168.0.18'}</td>
                        <td>{idx % 2 === 0 ? 'TCP' : 'UDP'}</td>
                        <td>{item.severity || 'HIGH'}</td>
                        <td>{item.risk_score ?? item.risk ?? 82}</td>
                        <td>{Number(item.risk_score ?? item.risk ?? 0) >= 80 ? 'Contained' : 'Monitored'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Endpoint Security':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Device protection</p>
              <h2>Endpoint Security</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Protected endpoints', securityMetrics.activeEnvironments, 'Connected agents'],
                ['Detected threats', securityMetrics.criticalThreats || 3, 'Across managed devices'],
                ['Remediated', '12', 'Last 24 hours'],
                ['Response', 'Isolated', 'Current status'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Endpoint status</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Host</th><th>OS</th><th>Risk</th><th>Status</th><th>Action</th></tr></thead>
                  <tbody>
                    {protectedEnvironments.map((item, idx) => (
                      <tr key={`${item.id}-endpoint`}>
                        <td>{item.name}</td>
                        <td>{item.type}</td>
                        <td>{Math.max(35, item.threats * 20 + 40)}</td>
                        <td>Protected</td>
                        <td>{idx % 2 === 0 ? 'Monitor' : 'Isolate'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Cloud Security':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Cloud posture</p>
              <h2>Cloud Security</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Connected clouds', protectedEnvironments.filter((item) => item.type === 'Cloud').length || 1, 'Security connectors'],
                ['High risk events', securityMetrics.highRiskSignals || 6, 'Identity and workloads'],
                ['Misconfigurations', '3', 'Needs review'],
                ['Outcome', 'Hardened', 'Current posture'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Cloud security findings</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Asset</th><th>Risk</th><th>Finding</th><th>Recommended action</th></tr></thead>
                  <tbody>
                    <tr><td>Identity federation</td><td>High</td><td>Privilege drift</td><td>Revoke stale roles</td></tr>
                    <tr><td>Compute cluster</td><td>Medium</td><td>Public exposure</td><td>Restrict ingress</td></tr>
                    <tr><td>Storage bucket</td><td>High</td><td>Unscanned access</td><td>Enable policy validation</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Application Security':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Runtime protection</p>
              <h2>Application Security</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Protected apps', protectedEnvironments.filter((item) => item.type === 'Web Application').length || 1, 'Active services'],
                ['Auth anomalies', Math.max(2, securityMetrics.highRiskSignals), 'Login abuse'],
                ['API exposure', '2', 'Critical routes'],
                ['Outcome', 'Hardened', 'Current posture'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Application findings</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Service</th><th>Finding</th><th>Impact</th><th>Outcome</th></tr></thead>
                  <tbody>
                    <tr><td>Customer portal</td><td>Credential stuffing attempt</td><td>High</td><td>Blocked</td></tr>
                    <tr><td>Partner API</td><td>Rate limit breach</td><td>Medium</td><td>Rate-limited</td></tr>
                    <tr><td>Admin console</td><td>Privilege misuse</td><td>High</td><td>Review required</td></tr>
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Cryptography':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Trust and key control</p>
              <h2>Cryptography</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Hash algorithm', 'SHA-256', 'Integrity status'],
                ['Signature', signatureState.status, 'Verification state'],
                ['Key mode', signatureState.keyMode || 'Ed25519', 'Current key'],
                ['Outcome', signatureState.valid ? 'Verified' : 'Requires validation', 'Trust outcome'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Cryptographic posture</h3></div>
              <div className="detector-note">
                <span>Current result</span>
                <p>{signatureState.valid ? 'Signed evidence is valid and event integrity is confirmed.' : 'The current event requires verification before trust can be established.'}</p>
              </div>
            </div>
          </div>
        );
      case 'Incident Response':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Operational containment</p>
              <h2>Incident Response</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Open incidents', securityMetrics.openIncidents, 'Current queue'],
                ['Critical', incidentList.filter((item) => String(item.severity || '').toUpperCase() === 'CRITICAL').length, 'Escalated'],
                ['Containment', '3', 'Actions executed'],
                ['Outcome', 'In progress', 'Current response'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Incident queue</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>ID</th><th>Type</th><th>Severity</th><th>Status</th><th>Action</th></tr></thead>
                  <tbody>
                    {incidentList.map((item) => (
                      <tr key={item.id}>
                        <td>{item.id}</td>
                        <td>{item.threatType}</td>
                        <td>{item.severity}</td>
                        <td>{item.status}</td>
                        <td>{item.status === 'OPEN' ? 'Investigate' : item.status === 'INVESTIGATING' ? 'Contain' : 'Resolve'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Security Events':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Live event stream</p>
              <h2>Security Events</h2>
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Recent audit trail</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Timestamp</th><th>User</th><th>Action</th><th>Resource</th><th>Outcome</th></tr></thead>
                  <tbody>
                    {auditLogs.map((item, index) => (
                      <tr key={`${item.eventId || index}-audit`}>
                        <td>{item.timestamp}</td>
                        <td>{item.user}</td>
                        <td>{item.action}</td>
                        <td>{item.resource}</td>
                        <td>{item.signatureStatus || 'VALID'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Risk Analysis':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Quantified exposure</p>
              <h2>Risk Analysis</h2>
            </div>
            <div className="stat-grid stat-grid--four">
              {[
                ['Average risk', `${securityMetrics.avgRisk}/100`, 'Current signal score'],
                ['Critical threats', securityMetrics.criticalThreats, 'High-priority exposures'],
                ['High-risk signals', securityMetrics.highRiskSignals, 'Above policy threshold'],
                ['Outcome', securityMetrics.avgRisk >= 70 ? 'Escalate' : 'Monitor', 'Recommendation'],
              ].map(([label, value, meta]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value">{value}</div>
                  <div className="stat-trend">{meta}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head"><h3>Risk drivers</h3></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>Factor</th><th>Risk</th><th>Impact</th><th>Recommended response</th></tr></thead>
                  <tbody>
                    {[
                      ['Privilege escalation', 91, 'System takeover risk', 'Isolate endpoint and revoke sessions'],
                      ['Credential abuse', 88, 'Identity compromise', 'Reset credentials and enforce MFA'],
                      ['Cloud misconfiguration', 76, 'Cross-environment exposure', 'Harden access policies'],
                    ].map(([factor, risk, impact, response]) => (
                      <tr key={factor}><td>{factor}</td><td>{risk}</td><td>{impact}</td><td>{response}</td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        );
      case 'Reports':
        return (
          <div className="page-stack">
            <div className="section-head">
              <div>
                <p className="section-kicker">Executive reporting</p>
                <h2>Security Report</h2>
              </div>
              <button className="primary-btn" type="button" onClick={() => window.print()}>Download Report</button>
            </div>

            <div className="report-shell glass-panel panel">
              <div className="report-watermark">CONFIDENTIAL</div>
              <div className="report-header">
                <div className="report-brand">
                  <img src="/quantum-cyber-defense-shield.svg" alt="Quantum Cyber Defense shield" />
                  <div>
                  <p className="section-kicker">Universal Quantum Security System</p>
                  <h3>Security Operations Report</h3>
                      <span className="report-generated-at">Generated {reportGeneratedAt.toLocaleString()}</span>
                  </div>
                </div>
                <div className="report-invoice-box">
                  <span>Invoice</span>
                  <p className="report-refresh-status" aria-live="polite">Auto-generated every 60 seconds · Latest: {reportGeneratedAt.toLocaleTimeString()}</p>
                  <strong>UQSS-2026-091</strong>
                </div>
              </div>

              <div className="report-meta-grid">
                <div>
                  <span>Client</span>
                  <strong>Global Digital Defense</strong>
                </div>
                <div>
                  <span>Period</span>
                  <strong>Sep 01 - Sep 30, 2026</strong>
                </div>
                <div>
                  <span>Security score</span>
                  <strong>{securityMetrics.score}/100</strong>
                </div>
                <div>
                  <span>Current status</span>
                  <strong>Monitoring active</strong>
                </div>
              </div>

              <div className="report-summary-grid">
                <div className="report-summary-item">
                  <span>Protected environments</span>
                  <strong>{securityMetrics.activeEnvironments}</strong>
                </div>
                <div className="report-summary-item">
                  <span>Critical threats</span>
                  <strong>{securityMetrics.criticalThreats}</strong>
                </div>
                <div className="report-summary-item">
                  <span>Open incidents</span>
                  <strong>{securityMetrics.openIncidents}</strong>
                </div>
                <div className="report-summary-item">
                  <span>Average risk</span>
                  <strong>{securityMetrics.avgRisk}/100</strong>
                </div>
              </div>

              <div className="report-content-grid">
                <div className="glass-panel panel panel--tight">
                  <div className="panel__head"><h3>Security outcome</h3></div>
                  <div className="detector-note">
                    <span>Summary</span>
                    <p>The Universal Security Gateway normalized telemetry from protected environments and correlated the highest-risk events across endpoints, cloud, and application services. The shared security engine identified a manageable number of escalated conditions and kept the security posture within a monitored range.</p>
                  </div>
                  <div className="detector-note">
                    <span>Observed result</span>
                    <p>{reportThreatCount} threats were observed, including {securityMetrics.highRiskSignals} high-risk signals and {securityMetrics.criticalThreats} critical threats. The BTC estimate scales with the threat count at 0.0245 BTC per threat.</p>
                  </div>
                </div>

                <div className="glass-panel panel panel--tight">
                  <div className="panel__head"><h3>Invoice · BTC equivalent</h3></div>
                  <div className="invoice-lines">
                    {baseInvoiceLines.map(([label, baseAmount]) => (
                      <div key={label}>
                        <span>{label}</span>
                        <strong>{(baseAmount * reportThreatCount / invoiceBaselineThreatCount).toFixed(4)} BTC</strong>
                      </div>
                    ))}
                  </div>
                  <div className="invoice-total">
                    <span>Total</span>
                    <strong>{reportInvoiceTotal.toFixed(4)} BTC</strong>
                  </div>
                  <p className="invoice-rate-note">{reportThreatCount} threats × 0.0245 BTC per threat. Indicative estimate; confirm the BTC settlement rate at payment.</p>
                </div>
              </div>

              <div className="glass-panel panel">
                <div className="panel__head"><h3>Threat summary</h3></div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr><th>Threat</th><th>Platform</th><th>Severity</th><th>Risk</th><th>Outcome</th></tr>
                    </thead>
                    <tbody>
                      {(timelineThreats.slice(0, 4)).map((item, index) => (
                        <tr key={`${item.id || index}-report`}>
                          <td>{item.classification || 'Credential abuse'}</td>
                          <td>{index === 0 ? 'Linux Server' : index === 1 ? 'Cloud' : index === 2 ? 'Web Application' : 'Windows'}</td>
                          <td>{item.severity || 'HIGH'}</td>
                          <td>{item.risk_score ?? item.risk ?? 84}</td>
                          <td>{Number(item.risk_score ?? item.risk ?? 0) >= 80 ? 'Contained' : 'Monitored'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        );
      case 'Integrations':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">Model and data providers</p>
              <h2>Integrations</h2>
            </div>
            <div className="stat-grid stat-grid--three">
              {[
                ['AI provider', aiStatus?.provider || 'Ollama · Llama 3.2'],
                ['Credential status', aiStatus ? (aiStatus.configured ? 'Configured on server' : 'Not configured') : 'Checking'],
                ['Active model', aiStatus?.model || 'llama3.2:3B'],
              ].map(([label, value]) => (
                <div key={label} className="glass-panel stat-card">
                  <span className="stat-label">{label}</span>
                  <div className="stat-card__value copilot-stat-value">{value}</div>
                </div>
              ))}
            </div>
            <div className="glass-panel panel">
              <div className="panel__head">
                <h3>Ollama · Llama 3.2</h3>
                <span className={`badge border ${aiStatus?.configured ? statusColors.VALID : statusColors.default}`}>
                  {aiStatus?.configured ? 'CONFIGURED' : 'SETUP REQUIRED'}
                </span>
              </div>
              <div className="detector-note">
                <span>Server-side configuration</span>
                <p>Install Ollama, run ollama pull llama3.2:3B, and set OLLAMA_MODEL in the project .env, then restart the backend. The model runs locally on the server and is never sent to the browser. When Ollama is unavailable, deterministic detection and existing remediation guidance continue to work.</p>
              </div>
              <div className="integration-capabilities">
                {(aiStatus?.capabilities || ['Threat explanation', 'Dashboard briefings', 'Security copilot']).map((capability) => (
                  <span key={capability} className="badge border">{capability}</span>
                ))}
              </div>
              <div className="verification-actions">
                <button type="button" className="secondary-btn" onClick={() => {
                  fetch('/api/ai/status', { headers: { Authorization: `Bearer ${authToken}` } })
                    .then((response) => response.ok ? response.json() : Promise.reject(new Error('Unable to load status')))
                    .then(setAiStatus)
                    .catch(() => setAiStatus(null));
                }}>Refresh status</button>
                <button type="button" className="primary-btn" onClick={() => openCopilot('Integrations', 'Review the AI and security data integration status. What should be checked next?')}>Analyze integrations</button>
              </div>
            </div>
          </div>
        );
      case 'Settings':
        return (
          <div className="page-stack">
            <div>
              <p className="section-kicker">System controls</p>
              <h2>Settings</h2>
            </div>
            <div className="setting-grid">
              {[
                ['Detection Settings', ['Risk Threshold', '80', 'Alert Threshold', '70']],
                ['Model', ['Model Name', 'QuantumNet v2', 'Model Version', '2.1.0', 'Feature Count', '14']],
                ['Security', ['Signature Algorithm', 'Ed25519', 'Hash Algorithm', 'SHA-256']],
                ['System', ['API Status', 'Operational', 'Database Status', 'Healthy', 'Model Status', 'Ready']],
              ].map(([title, rows]) => (
                <div key={title} className="glass-panel panel panel--settings">
                  <div className="panel__head">
                    <h3>{title}</h3>
                  </div>
                  <div className="settings-list">
                    {rows.map((row, index) => {
                      if (index % 2 === 0) {
                        return (
                          <div key={`${title}-${row}`} className="settings-row">
                            <span>{row}</span>
                            <strong>{rows[index + 1]}</strong>
                          </div>
                        );
                      }
                      return null;
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      default:
        return <div className="text-white">Page not found</div>;
    }
  };

  return (
    <div
      className="cyber-shell"
      onMouseMove={handleLayoutPointerMove}
    >
      {isLoggedIn && (
        <aside className="sidebar glass-panel">
          <div className="brand-block">
            <img className="brand-mark" src="/quantum-cyber-defense-shield.svg" alt="Quantum Cyber Defense shield" />
            <div>
              <div className="brand-name">Quantum Cyber</div>
              <div className="brand-subtitle">Defense Grid</div>
            </div>
          </div>

          <button type="button" className="back-button" onClick={handleBackToLogin}>
            <span className="back-button__icon">←</span>
            Back
          </button>

          <nav className="nav-list">
            {visibleNavItems.map((item) => (
              <button
                key={item}
                onClick={() => setPage(item)}
                className={`nav-item ${page === item ? 'nav-item--active' : ''}`}
              >
                <span>{item}</span>
              </button>
            ))}
          </nav>

          <div className="sidebar-status">
            <span className="status-dot" />
            <span>Systems operational</span>
          </div>

          <div className="profile-card">
            <div className="profile-avatar">{isAdmin ? 'AD' : 'CU'}</div>
            <div>
              <div className="profile-name">{isAdmin ? 'System Admin' : 'Customer Portal'}</div>
              <div className="profile-role">{isAdmin ? 'Admin' : 'Customer'}</div>
            </div>
          </div>
        </aside>
      )}

      <main className="main-panel">
        {isLoggedIn && (
          <header className="topbar glass-panel">
            <div>
              <p className="topbar-label">Threat posture</p>
              <h3>Global Defense Matrix</h3>
            </div>
            <div className="topbar__right">
              <div className={`pill ${liveMonitoring ? 'pill--live' : ''}`}>{liveMonitoring ? 'LIVE' : 'STANDBY'}</div>
              <div className="pill">{new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</div>
            </div>
          </header>
        )}

        <div className="page-content">{renderPage()}</div>
      </main>
    </div>
  );
}

export default App;
