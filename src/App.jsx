import React, { useState, useEffect, useMemo, useRef } from 'react';
import { 
  Shield, AlertTriangle, Activity, Database, FileText, Lock, User, Terminal, 
  Globe, Download, Zap, RefreshCw, Trash2, Plus, Briefcase, Building2, Mail, 
  ArrowLeft, Calendar, Layers, BarChart3, Lightbulb, CheckCircle, TrendingUp, 
  TrendingDown, Search, Clock, Map, Server, CheckSquare, AlertOctagon, Ban, 
  ThumbsUp, Check 
} from 'lucide-react';
import { 
  ResponsiveContainer, PieChart, Pie, Cell, RadarChart, PolarGrid, 
  PolarAngleAxis, PolarRadiusAxis, Radar, Tooltip, Legend, LineChart, 
  Line, BarChart, Bar, XAxis, YAxis, CartesianGrid 
} from 'recharts';
import { initializeApp } from 'firebase/app';
import { 
  getAuth, onAuthStateChanged, createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, signOut, updateProfile, sendPasswordResetEmail 
} from 'firebase/auth';
import { 
  getFirestore, collection, addDoc, setDoc, getDoc, updateDoc, query, 
  onSnapshot, doc, deleteDoc, serverTimestamp, orderBy, writeBatch 
} from 'firebase/firestore'; 

// --- CONFIGURATION ---
const firebaseConfig = {
  apiKey: "AIzaSyCY79omhIz4y0meZdz6bEyuoajHY6hL2Rw",
  authDomain: "sentinel-cyber.firebaseapp.com",
  projectId: "sentinel-cyber",
  storageBucket: "sentinel-cyber.firebasestorage.app",
  messagingSenderId: "328311767668",
  appId: "1:328311767668:web:915f82d081784227e54721",
  measurementId: "G-HTNYJ2N8HK"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
const appId = "production-v1"; 

// --- UTILITIES ---
const PATTERNS = {
  SQL_INJECTION: /(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b.*(--|\bFROM\b)|'(\s)*(=|OR|AND)|"(\s)*(=|OR|AND))/i,
  XSS: /(<script>|javascript:|on(load|click|error|mouseover)=|%3Cscript%3E)/i,
  BRUTE_FORCE: /(failed login|invalid password|access denied|authentication failure)/i,
  PII_EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/,
  PII_CREDIT_CARD: /\b(?:\d{4}[- ]?){3}\d{4}\b/,
  TRAVERSAL: /(\.\.\/|\.\.\\)/,
  DATE_EXTRACT: /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})|(\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2})|(\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{4}\s+\d{2}:\d{2}:\d{2})/i
};

const analyzeLogLine = (line, source = 'manual', timestampOverride = null) => {
  let generationTime = timestampOverride ? new Date(timestampOverride) : new Date();
  
  if (!timestampOverride) {
      const dateMatch = line.match(PATTERNS.DATE_EXTRACT);
      if (dateMatch) {
        const parsed = new Date(dateMatch[0]);
        if (!isNaN(parsed.getTime())) generationTime = parsed;
      }
  }

  let severity = 'Low';
  let threatType = 'Clean';
  let compliance = [];
  
  if (PATTERNS.SQL_INJECTION.test(line)) { severity = 'Critical'; threatType = 'SQL Injection'; compliance.push('OWASP Top 10'); } 
  else if (PATTERNS.XSS.test(line)) { severity = 'High'; threatType = 'XSS'; compliance.push('OWASP Top 10'); } 
  else if (PATTERNS.BRUTE_FORCE.test(line)) { severity = 'Medium'; threatType = 'Brute Force Attempt'; } 
  else if (PATTERNS.TRAVERSAL.test(line)) { severity = 'High'; threatType = 'Path Traversal'; }

  if (PATTERNS.PII_EMAIL.test(line)) { compliance.push('GDPR'); if (severity === 'Low') severity = 'Medium'; if (threatType === 'Clean') threatType = 'Data Leakage (Email)'; }
  if (PATTERNS.PII_CREDIT_CARD.test(line)) { compliance.push('PCI-DSS'); severity = 'Critical'; threatType = 'Data Leakage (Credit Card)'; }
  if (/\b(password|passwd|secret|key)\s*[:=]\s*\S+/i.test(line)) { compliance.push('ISO 27001'); severity = 'High'; threatType = 'Credential Exposure'; }

  const ipMatch = line.match(/(?:[0-9]{1,3}\.){3}[0-9]{1,3}/);
  const ip = ipMatch ? ipMatch[0] : 'Unknown';

  return {
    id: crypto.randomUUID(),
    raw: line,
    timestamp: generationTime.toISOString(),
    logGenerationTime: generationTime.toISOString(),
    severity,
    type: threatType,
    compliance,
    source,
    ip,
    status: 'New' 
  };
};

const calculateAnalytics = (logs) => {
    const total = logs.length;
    const critical = logs.filter(l => l.severity === 'Critical').length;
    const complianceScore = total > 0 ? Math.round(((total - logs.filter(l => l.compliance.length > 0).length) / total) * 100) : 100;
    
    const now = new Date();
    const oneWeekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const currentPeriod = logs.filter(l => new Date(l.timestamp) >= oneWeekAgo);
    const velocity = logs.length > 0 ? (currentPeriod.length / logs.length) * 100 : 0;

    const heatmapData = Array(7).fill(null).map(() => Array(24).fill(0));
    logs.forEach(log => {
        const d = new Date(log.timestamp);
        if(!isNaN(d)) heatmapData[d.getDay()][d.getHours()]++;
    });

    const ipCounts = logs.reduce((acc, log) => {
        if (log.ip !== 'Unknown' && log.severity !== 'Clean') acc[log.ip] = (acc[log.ip] || 0) + 1;
        return acc;
    }, {});
    const topIPs = Object.entries(ipCounts).sort(([, a], [, b]) => b - a).slice(0, 5).map(([ip, count]) => ({ ip, count }));

    const timelineData = logs.reduce((acc, log) => {
        const dateKey = new Date(log.timestamp).toISOString().split('T')[0];
        if (!acc[dateKey]) acc[dateKey] = { date: dateKey, gdpr: 0, pci: 0 };
        if (log.compliance.includes('GDPR')) acc[dateKey].gdpr++;
        if (log.compliance.includes('PCI-DSS')) acc[dateKey].pci++;
        return acc;
    }, {});
    const complianceTimeline = Object.values(timelineData).sort((a, b) => new Date(a.date) - new Date(b.date));

    const typeCount = logs.reduce((acc, curr) => { acc[curr.type] = (acc[curr.type] || 0) + 1; return acc; }, {});
    const pieData = Object.keys(typeCount).map(k => ({ name: k, value: typeCount[k] }));

    return { 
        total, critical, complianceScore, velocity, mttdMinutes: 12, 
        heatmapData, topIPs, complianceTimeline, pieData,
        topRiskyAssets: topIPs.map(i => ({...i, score: i.count * 5, critical: Math.floor(i.count/2), high: Math.floor(i.count/2)})), 
        geoLocations: topIPs.map(i => ({ ip: i.ip, score: i.count, x: (parseInt(i.ip.split('.')[0]) % 90), y: (parseInt(i.ip.split('.')[1]) % 80) })),
        fpr: 2.4 
    };
};

const generateAIAnalysis = (logs) => {
    const totalLogs = logs.length;
    const critical = logs.filter(l => l.severity === 'Critical').length;
    const high = logs.filter(l => l.severity === 'High').length;
    const medium = logs.filter(l => l.severity === 'Medium').length;
    
    const threats = logs.reduce((acc, l) => {
        if(l.type !== 'Clean') acc[l.type] = (acc[l.type] || 0) + 1;
        return acc;
    }, {});
    const dominantThreat = Object.keys(threats).sort((a,b) => threats[b] - threats[a])[0] || "None";

    const compliance = {
        gdpr: logs.filter(l => l.compliance.includes('GDPR')).length,
        pci: logs.filter(l => l.compliance.includes('PCI-DSS')).length,
        owasp: logs.filter(l => l.compliance.includes('OWASP Top 10')).length
    };

    let narrative = `The current security posture indicates a ${critical > 0 ? 'CRITICAL' : 'STABLE'} status based on ${totalLogs} analyzed events. `;
    if (critical > 0) narrative += `Immediate attention is required for ${critical} critical incidents, primarily driven by ${dominantThreat}. `;
    else narrative += `No critical breaches detected, though ${medium} medium-severity events suggest potential misconfigurations. `;
    
    if (compliance.pci > 0) narrative += `PCI-DSS compliance is compromised (${compliance.pci} violations), indicating potential financial data leakage. `;
    if (compliance.gdpr > 0) narrative += `GDPR exposure detected (${compliance.gdpr} events), risking PII regulatory penalties. `;

    let forecastText = "Based on current velocity, threat volume is stable.";
    if (critical > 5) forecastText = "Threat velocity is accelerating. Expect a 15% increase in brute force attempts over the next 48 hours unless IP blocking is enforced.";
    
    const steps = [];
    if (critical > 0) steps.push("Initiate Incident Response Protocol Alpha for Critical IP containment.");
    if (threats['SQL Injection']) steps.push("Audit WAF rules for SQLi patterns and sanitize database inputs.");
    if (threats['XSS']) steps.push("Review Content Security Policy (CSP) headers on public-facing apps.");
    if (compliance.pci > 0) steps.push("Isolate payment gateway logs and scrub credit card patterns immediately.");
    if (steps.length === 0) steps.push("Maintain standard monitoring. Review False Positive rules to optimize engine noise.");

    return {
        summary: narrative,
        threats,
        compliance,
        forecast: forecastText,
        actionableSteps: steps,
        dominantThreat
    };
};

// --- MAIN APPLICATION ---
export default function App() {
  const [user, setUser] = useState(null);
  const [userProfile, setUserProfile] = useState(null);
  const [view, setView] = useState('login'); 
  const [logs, setLogs] = useState([]);
  const [rules, setRules] = useState([]);
  const [activeConnection, setActiveConnection] = useState(null);
  const [loading, setLoading] = useState(true);
  
  // --- LIVE POLLING ENGINE (OPTIMIZED) ---
  useEffect(() => {
    let interval;
    // Only run polling if we have an active connection AND are in the dashboard/terminal view
    if (activeConnection && user) {
        interval = setInterval(async () => {
            try {
                // 1. Get timestamp of the very last log in our array
                const lastLog = logs.length > 0 ? logs[logs.length - 1] : null;
                const lastTimestamp = lastLog ? lastLog.timestamp : null;

                // 2. Fetch new logs from backend
                const response = await fetch('http://localhost:5000/api/connect-db', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ ...activeConnection, last_timestamp: lastTimestamp })
                });
                
                const data = await response.json();
                
                // 3. If new logs arrive, append them cleanly
                if (data.success && data.logs.length > 0) {
                    console.log(`🔥 Frontend received ${data.logs.length} new logs from stream.`);
                    const newAnalyzedLogs = data.logs.map(l => analyzeLogLine(l.raw, l.source, l.timestamp));
                    
                    setLogs(prev => {
                        // Optimization: Only check against the last 100 logs for duplicates to save performance
                        const recentLogs = prev.slice(-100); 
                        const existingHashes = new Set(recentLogs.map(l => l.timestamp + l.raw));
                        const uniqueNew = newAnalyzedLogs.filter(l => !existingHashes.has(l.timestamp + l.raw));
                        
                        if (uniqueNew.length > 0) {
                            return [...prev, ...uniqueNew];
                        }
                        return prev;
                    });
                }
            } catch (err) {
                // Silent fail for polling to avoid console spam if backend momentarily offline
            }
        }, 4000); // 4s poll for responsiveness
    }
    return () => clearInterval(interval);
  }, [activeConnection, logs, user]); // Dependencies ensure it stays fresh

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, async (currentUser) => {
      setUser(currentUser);
      if (currentUser) {
        const profileDoc = await getDoc(doc(db, 'artifacts', appId, 'users', currentUser.uid, 'profile', 'data'));
        if (profileDoc.exists()) setUserProfile(profileDoc.data());
        setView('dashboard');
      } else setView('login');
      setLoading(false);
    });
    return () => unsubscribe();
  }, []);

  useEffect(() => {
    if (!user) return;
    const qRules = query(collection(db, 'artifacts', appId, 'users', user.uid, 'rules'));
    const unsubRules = onSnapshot(qRules, (snap) => {
      setRules(snap.docs.map(d => ({ id: d.id, ...d.data() })));
    }, (err) => console.error("Rule sync error", err));
    return () => unsubRules();
  }, [user]);

  // Called when DB Connects initially
  const handleConnectionEstablished = (initialLogs, connectionConfig) => {
      setActiveConnection(connectionConfig);
      const analyzed = initialLogs.map(l => analyzeLogLine(l.raw, l.source, l.timestamp));
      // Overwrite logs on new connection, don't append to stale data
      setLogs(analyzed); 
  };

  const handleIngest = async (text, source) => {
    if (!user) return;
    const lines = text.split(/\r?\n/);
    const newLogs = [];
    lines.forEach(line => {
        if(line.trim()) newLogs.push(analyzeLogLine(line, source));
    });
    setLogs(prev => [...prev, ...newLogs]);
  };

  const handleLogout = async () => { await signOut(auth); setUserProfile(null); setActiveConnection(null); };

  if (loading) return <div className="h-screen w-full bg-slate-950 flex items-center justify-center text-cyan-500 font-mono">INITIALIZING...</div>;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 font-sans selection:bg-cyan-500/30">
      <div className="fixed inset-0 bg-[url('https://grainy-gradients.vercel.app/noise.svg')] opacity-20 pointer-events-none"></div>
      {!user ? <AuthScreen /> : (
        <div className="relative z-10 flex h-screen overflow-hidden">
          <Sidebar view={view} setView={setView} onLogout={handleLogout} />
          <main className="flex-1 overflow-y-auto p-6">
            <Header userProfile={userProfile} user={user} activeConnection={activeConnection} />
            {view === 'dashboard' && <Dashboard logs={logs} user={user} />}
            {view === 'ingest' && <IngestCenter onIngest={handleIngest} />}
            {view === 'terminal' && <LiveTerminal logs={logs} onIngest={handleIngest} />}
            {view === 'automation' && <AutomationCenter rules={rules} userId={user.uid} />}
            {view === 'reports' && <ReportCenter logs={logs} userProfile={userProfile} />}
            {view === 'connectors' && <DBConnectors onConnectionEstablished={handleConnectionEstablished} />}
            {view === 'copilot' && <AICopilot logs={logs} />}
          </main>
        </div>
      )}
    </div>
  );
}

// --- SUB COMPONENTS ---

const Card = ({ children, className = "" }) => (
  <div className={`bg-slate-900/50 backdrop-blur-md border border-slate-700/50 p-6 rounded-xl shadow-xl ${className}`}>
    {children}
  </div>
);

const Badge = ({ severity }) => {
  const colors = {
    Critical: 'bg-red-500/20 text-red-400 border-red-500/50',
    High: 'bg-orange-500/20 text-orange-400 border-orange-500/50',
    Medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50',
    Low: 'bg-green-500/20 text-green-400 border-green-500/50',
    Clean: 'bg-blue-500/20 text-blue-400 border-blue-500/50'
  };
  return (
    <span className={`px-2 py-1 rounded text-xs border font-medium ${colors[severity] || colors.Clean}`}>
      {severity}
    </span>
  );
};

const WorldMap = ({ locations }) => {
  return (
    <div className="relative w-full h-full min-h-[300px] bg-slate-900/50 rounded-lg overflow-hidden flex items-center justify-center">
       <svg viewBox="0 0 800 400" className="w-full h-full opacity-40">
         <path fill="#334155" d="M150,120 Q180,60 250,80 T350,100 T450,90 T550,80 T650,100 Q750,120 700,200 T550,300 T400,320 T250,300 T100,250 Z M50,100 Q80,80 100,120 T80,180 Z" />
         <rect width="800" height="400" fill="transparent" />
         <defs>
            <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
              <circle cx="1" cy="1" r="1" fill="#1e293b" />
            </pattern>
         </defs>
         <rect width="100%" height="100%" fill="url(#grid)" />
       </svg>
       {locations.map((loc, i) => (
         <div key={i} className="absolute w-3 h-3 bg-red-500 rounded-full shadow-[0_0_10px_rgba(239,68,68,0.8)] animate-pulse" style={{ top: `${loc.y}%`, left: `${loc.x}%` }} title={`IP: ${loc.ip} - Score: ${loc.score}`}></div>
       ))}
       <div className="absolute bottom-4 left-4 text-xs text-slate-500 bg-slate-900/80 px-2 py-1 rounded border border-slate-700">Live Threat Origins (Simulated View)</div>
    </div>
  );
};

const Header = ({ userProfile, user, activeConnection }) => (
    <header className="flex justify-between items-center mb-8 border-b border-slate-800 pb-4">
        <div>
            <h1 className="text-2xl font-bold text-white tracking-wider flex items-center gap-2">
                <Shield className="w-6 h-6 text-cyan-400" /> Sentinel <span className="text-cyan-500 text-sm bg-cyan-950/50 px-2 py-0.5 rounded border border-cyan-800">PRO v2.4</span>
            </h1>
            <p className="text-slate-400 text-xs font-mono mt-1 flex items-center gap-2">
                {activeConnection ? <span className="text-emerald-400 animate-pulse">● LIVE STREAMING: {activeConnection.host}</span> : 'OFFLINE MODE'} 
                :: {userProfile?.company || 'ORG'}
            </p>
        </div>
        <div className="w-10 h-10 rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center border-2 border-slate-900 shadow-lg"><User className="w-5 h-5 text-white" /></div>
    </header>
);

const AuthScreen = () => {
  const [authMode, setAuthMode] = useState('login'); 
  const [formData, setFormData] = useState({ email: '', password: '', fullName: '', company: '', role: '', industry: 'Technology' });
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const handleChange = (e) => setFormData({...formData, [e.target.name]: e.target.value});
  const handleSubmit = async (e) => {
    e.preventDefault(); setError(''); setMessage('');
    try {
      if (authMode === 'login') await signInWithEmailAndPassword(auth, formData.email, formData.password);
      else if (authMode === 'register') {
        const userCredential = await createUserWithEmailAndPassword(auth, formData.email, formData.password);
        await setDoc(doc(db, 'artifacts', appId, 'users', userCredential.user.uid, 'profile', 'data'), {
          fullName: formData.fullName, company: formData.company, role: formData.role, industry: formData.industry, email: formData.email, createdAt: serverTimestamp()
        });
        await updateProfile(userCredential.user, { displayName: formData.fullName });
      } else if (authMode === 'forgot') {
        await sendPasswordResetEmail(auth, formData.email); setMessage('Password reset link sent.');
      }
    } catch (err) { setError(err.message.replace('Firebase: ', '')); }
  };
  return (
    <div className="h-screen w-full flex items-center justify-center relative z-20 px-4">
      <Card className="w-full max-w-md border-cyan-500/30 shadow-[0_0_50px_rgba(6,182,212,0.15)] bg-slate-950/80">
        <div className="text-center mb-6">
          <Shield className="w-12 h-12 text-cyan-400 mx-auto mb-4" />
          <h2 className="text-3xl font-bold text-white mb-2">Sentinel Platform</h2>
          <p className="text-slate-400 text-sm">{authMode === 'login' ? 'Secure Identity Verification' : 'Agent Onboarding'}</p>
        </div>
        {error && <div className="bg-red-500/20 border border-red-500/50 text-red-300 p-3 rounded mb-4 text-xs font-mono">{error}</div>}
        {message && <div className="bg-green-500/20 border border-green-500/50 text-green-300 p-3 rounded mb-4 text-xs font-mono">{message}</div>}
        <form onSubmit={handleSubmit} className="space-y-4">
          {authMode === 'register' && (
            <>
              <div className="grid grid-cols-2 gap-4">
                <input name="fullName" required placeholder="Name" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white w-full" onChange={handleChange} />
                <input name="role" required placeholder="Role" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white w-full" onChange={handleChange} />
              </div>
              <input name="company" required placeholder="Company" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white w-full" onChange={handleChange} />
            </>
          )}
          <input type="email" name="email" required placeholder="Email" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white w-full" onChange={handleChange} />
          {authMode !== 'forgot' && <input type="password" name="password" required placeholder="Password" className="bg-slate-900 border border-slate-700 rounded p-2 text-sm text-white w-full" onChange={handleChange} />}
          <button className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-bold py-2 rounded uppercase text-sm">Submit</button>
        </form>
        <div className="mt-4 flex justify-between text-xs text-slate-500">
            <button onClick={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}>{authMode === 'login' ? 'Create Account' : 'Login'}</button>
            {authMode === 'login' && <button onClick={() => setAuthMode('forgot')}>Forgot?</button>}
        </div>
      </Card>
    </div>
  );
};

const Sidebar = ({ view, setView, onLogout }) => {
  const menu = [
    { id: 'dashboard', icon: Activity, label: 'Overview' },
    { id: 'ingest', icon: FileText, label: 'Log Ingestion' },
    { id: 'connectors', icon: Database, label: 'DB Connectors' },
    { id: 'terminal', icon: Terminal, label: 'Live Terminal' },
    { id: 'automation', icon: Zap, label: 'Automation' },
    { id: 'reports', icon: Download, label: 'Reports & Export' },
    { id: 'copilot', icon: Lightbulb, label: 'AI Copilot' },
  ];
  return (
    <aside className="w-20 md:w-64 flex-shrink-0 border-r border-slate-800 bg-slate-900/30 flex flex-col justify-between backdrop-blur-sm">
      <div className="p-4 space-y-2">
        {menu.map(item => (
          <button key={item.id} onClick={() => setView(item.id)} className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${view === item.id ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30' : 'text-slate-400 hover:bg-slate-800 hover:text-white'}`}>
            <item.icon className="w-5 h-5" /><span className="hidden md:block font-medium text-sm">{item.label}</span>
          </button>
        ))}
      </div>
      <div className="p-4 border-t border-slate-800">
        <button onClick={onLogout} className="w-full flex items-center gap-3 px-4 py-3 rounded-lg text-red-400 hover:bg-red-500/10 transition-colors"><Lock className="w-5 h-5" /><span className="hidden md:block font-medium text-sm">Terminate</span></button>
      </div>
    </aside>
  );
};

const DBConnectors = ({ onConnectionEstablished }) => {
  const [formData, setFormData] = useState({ type: 'mysql', host: 'localhost', port: '3306', user: 'root', password: '', database: 'sentinel_logs' });
  const [loading, setLoading] = useState(false);

  const handleConnect = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
        const response = await fetch('http://localhost:5000/api/connect-db', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(formData)
        });
        const data = await response.json();
        
        if (data.success) {
            if (onConnectionEstablished) {
                onConnectionEstablished(data.logs, formData);
            }
            alert(`Connected! Fetched ${data.logs.length} logs. Live streaming active.`);
        } else {
            alert(`Connection Failed: ${data.message}`);
        }
    } catch (err) { alert("API Error: Backend not running."); } 
    finally { setLoading(false); }
  };

  return (
    <div className="max-w-2xl mx-auto">
      <Card>
        <h2 className="text-xl font-bold text-white mb-6 flex items-center gap-2"><Database className="w-5 h-5 text-cyan-400"/> Live Connector</h2>
        <form onSubmit={handleConnect} className="space-y-4">
           <div className="grid grid-cols-2 gap-4">
              <select className="bg-slate-900 text-white p-2 rounded border border-slate-700" onChange={e => setFormData({...formData, type: e.target.value})}><option value="mysql">MySQL</option><option value="postgresql">PostgreSQL</option></select>
              <input className="bg-slate-900 text-white p-2 rounded border border-slate-700" placeholder="Host" value={formData.host} onChange={e => setFormData({...formData, host: e.target.value})} />
           </div>
           <div className="grid grid-cols-2 gap-4">
              <input className="bg-slate-900 text-white p-2 rounded border border-slate-700" placeholder="User" value={formData.user} onChange={e => setFormData({...formData, user: e.target.value})} />
              <input className="bg-slate-900 text-white p-2 rounded border border-slate-700" type="password" placeholder="Password" value={formData.password} onChange={e => setFormData({...formData, password: e.target.value})} />
           </div>
           <input className="bg-slate-900 text-white p-2 rounded border border-slate-700 w-full" placeholder="Database" value={formData.database} onChange={e => setFormData({...formData, database: e.target.value})} />
           <button disabled={loading} className="w-full bg-blue-600 text-white font-bold py-2 rounded">{loading ? 'Connecting...' : 'Start Live Stream'}</button>
        </form>
      </Card>
    </div>
  );
};

const Dashboard = ({ logs, user }) => {
  const stats = useMemo(() => calculateAnalytics(logs), [logs]);
  const COLORS = ['#06b6d4', '#ef4444', '#f59e0b', '#10b981', '#6366f1'];
  const DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

  const handleFalsePositive = async (logId) => {
    if (!user) return;
    try { await updateDoc(doc(db, 'artifacts', appId, 'users', user.uid, 'logs', logId), { status: 'False Positive' }); } catch (e) { console.error("Error marking False Positive", e); }
  };

  const handleBlockIP = async (log) => {
    if (!user) return;
    try {
      await addDoc(collection(db, 'artifacts', appId, 'users', user.uid, 'rules'), { name: `Manual Block ${log.ip}`, conditionField: 'ip', conditionValue: log.ip, action: 'BLOCK_IP' });
      await updateDoc(doc(db, 'artifacts', appId, 'users', user.uid, 'logs', log.id), { status: 'Blocked' });

      try {
          const response = await fetch('http://localhost:5000/api/block-ip', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ ip: log.ip })
          });
          const result = await response.json();
          if(result.success) console.log("Firewall updated successfully via Backend");
      } catch (apiErr) {
          console.warn("Backend API unreachable (Demo Mode Active):", apiErr);
      }
    } catch (e) {
      console.error("Error blocking IP", e);
    }
  };

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
        <Card className="border-t-4 border-t-cyan-500"><div className="text-slate-400 text-xs uppercase tracking-widest font-bold mb-2">Total Analyzed</div><div className="text-3xl font-mono text-white">{stats.total}</div></Card>
        <Card className="border-t-4 border-t-purple-500"><div className="text-purple-400 text-xs uppercase tracking-widest font-bold mb-2">Risk Velocity</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.velocity > 0 ? '+' : ''}{stats.velocity.toFixed(0)}%</div>{stats.velocity > 0 ? <TrendingUp className="w-6 h-6 text-red-500 mb-1" /> : <TrendingDown className="w-6 h-6 text-green-500 mb-1" />}</div></Card>
        <Card className="border-t-4 border-t-pink-500"><div className="text-pink-400 text-xs uppercase tracking-widest font-bold mb-2">MTTD</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.mttdMinutes}<span className="text-sm text-slate-500 ml-1">min</span></div><Clock className="w-6 h-6 text-pink-500 mb-1" /></div></Card>
        <Card className="border-t-4 border-t-emerald-500"><div className="text-emerald-400 text-xs uppercase tracking-widest font-bold mb-2">Compliance</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.complianceScore}%</div><CheckSquare className="w-6 h-6 text-emerald-500 mb-1" /></div></Card>
        <Card className="border-t-4 border-t-yellow-500"><div className="text-yellow-400 text-xs uppercase tracking-widest font-bold mb-2">False Positives</div><div className="flex items-end justify-between"><div className="text-3xl font-mono text-white">{stats.fpr.toFixed(1)}%</div><ThumbsUp className="w-6 h-6 text-yellow-500 mb-1" /></div></Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-1"><h3 className="text-white font-bold mb-4 flex items-center gap-2"><Server className="w-4 h-4 text-red-400"/> Risky Assets (Top 5)</h3><div className="space-y-3">{stats.topRiskyAssets.length > 0 ? stats.topRiskyAssets.map(asset => (<div key={asset.ip} className="flex items-center justify-between p-2 bg-slate-800/50 rounded border border-slate-700"><div><div className="font-mono text-sm text-white">{asset.ip}</div><div className="text-[10px] text-slate-500 flex gap-2"><span className="text-red-400">{asset.critical} Crit</span><span className="text-orange-400">{asset.high} High</span></div></div><div className="text-right"><div className="text-xl font-bold text-red-500">{asset.score}</div><div className="text-[10px] uppercase text-slate-600">Risk Score</div></div></div>)) : <div className="text-slate-500 text-sm italic">No risky assets detected.</div>}</div></Card>
        <Card className="lg:col-span-2 h-96"><h3 className="text-white font-bold mb-4 flex items-center gap-2"><Map className="w-4 h-4 text-cyan-400"/> Global Threat Origins (Simulated)</h3><WorldMap locations={stats.geoLocations} /></Card>
      </div>

      <Card>
        <h3 className="text-white font-bold mb-6 flex items-center gap-2"><Layers className="w-4 h-4 text-cyan-400"/> Temporal Threat Heatmap</h3>
        <div className="overflow-x-auto">
            <div className="min-w-[600px]">
                <div className="flex mb-2 ml-12">
                    {Array.from({length: 24}).map((_, i) => (<div key={i} className="flex-1 text-[10px] text-slate-500 text-center font-mono">{i.toString().padStart(2, '0')}</div>))}
                </div>
                <div className="space-y-1">
                    {stats.heatmapData.map((dayRow, dayIndex) => (
                        <div key={dayIndex} className="flex items-center h-8">
                            <div className="w-12 text-xs text-slate-400 font-bold uppercase">{DAYS[dayIndex]}</div>
                            <div className="flex-1 flex gap-1 h-full">
                                {dayRow.map((count, hourIndex) => {
                                    let bgClass = 'bg-slate-800';
                                    if (count > 0) bgClass = 'bg-cyan-900/40';
                                    if (count > 2) bgClass = 'bg-cyan-700/60';
                                    if (count > 5) bgClass = 'bg-cyan-500';
                                    if (count > 10) bgClass = 'bg-cyan-300';
                                    return (<div key={hourIndex} className={`flex-1 rounded-sm ${bgClass} hover:border hover:border-white transition-all relative group`}>
                                            {count > 0 && <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-1 bg-slate-900 text-white text-[10px] px-2 py-1 rounded hidden group-hover:block z-50 border border-slate-700">{DAYS[dayIndex]} @ {hourIndex}:00 - {count} Events</div>}
                                        </div>);
                                })}
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <Card className="h-80">
          <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Activity className="w-4 h-4 text-cyan-400"/> Threat Distribution</h3>
          <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={stats.pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value">
                  {stats.pieData.map((entry, index) => <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} stroke="rgba(0,0,0,0.5)" />)}
                </Pie>
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} itemStyle={{ color: '#fff' }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
        </Card>
        <Card className="h-80">
          <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Globe className="w-4 h-4 text-cyan-400"/> Risk Radar</h3>
          <ResponsiveContainer width="100%" height="100%">
            <RadarChart outerRadius={90} data={[
              { subject: 'SQLi', A: stats.critical * 20, fullMark: 100 },
              { subject: 'XSS', A: stats.high * 15, fullMark: 100 },
              { subject: 'GDPR', A: stats.gdpr * 25, fullMark: 100 },
              { subject: 'Auth', A: stats.medium * 10, fullMark: 100 },
              { subject: 'OWASP', A: stats.owasp * 10, fullMark: 100 },
            ]}>
              <PolarGrid stroke="#334155" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: '#94a3b8', fontSize: 12 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} stroke="#334155"/>
              <Radar name="Threat Level" dataKey="A" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.3} />
            </RadarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="lg:col-span-2 h-80">
          <h3 className="text-white font-bold mb-4 flex items-center gap-2"><Calendar className="w-4 h-4 text-yellow-400"/> Compliance Violation Timeline & Forecast</h3>
          <ResponsiveContainer width="100%" height="90%">
            <LineChart data={stats.complianceTimeline} margin={{ top: 5, right: 20, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="date" stroke="#94a3b8" tick={{ fontSize: 10 }} />
              <YAxis stroke="#94a3b8" />
              <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} itemStyle={{ color: '#fff' }} />
              <Legend />
              <Line type="monotone" dataKey="gdpr" name="GDPR PII (Actual)" stroke="#06b6d4" strokeWidth={2} dot={false} />
              <Line type="monotone" dataKey="pci" name="PCI-DSS Leakage (Actual)" stroke="#f97316" strokeWidth={2} dot={false} />
            </LineChart>
          </ResponsiveContainer>
        </Card>
        
        <Card className="lg:col-span-1 h-80">
          <h3 className="text-white font-bold mb-4 flex items-center gap-2"><BarChart3 className="w-4 h-4 text-red-400"/> Top 5 Attacking IPs</h3>
          <ResponsiveContainer width="100%" height="90%">
            <BarChart layout="vertical" data={stats.topIPs} margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis type="number" stroke="#94a3b8" />
                <YAxis dataKey="ip" type="category" stroke="#94a3b8" tick={{ fontSize: 10 }} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155' }} itemStyle={{ color: '#fff' }} />
                <Bar dataKey="count" fill="#ef4444" name="Threat Count" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      <Card>
        <h3 className="text-white font-bold mb-4">Recent Alerts & Remediation</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left text-slate-400">
            <thead className="text-xs text-slate-500 uppercase bg-slate-800/50">
              <tr><th className="px-4 py-3">Timestamp</th><th className="px-4 py-3">Severity</th><th className="px-4 py-3">Type</th><th className="px-4 py-3">Status</th><th className="px-4 py-3">Actions</th></tr>
            </thead>
            <tbody>
              {logs.slice(0, 8).map(log => (
                <tr key={log.id} className={`border-b border-slate-800 hover:bg-slate-800/30 ${log.status === 'Blocked' ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-3 font-mono text-xs">{new Date(log.timestamp).toLocaleTimeString()}</td>
                  <td className="px-4 py-3"><Badge severity={log.severity} /></td>
                  <td className="px-4 py-3 text-white">{log.type}</td>
                  <td className="px-4 py-3"><span className={`text-xs px-2 py-1 rounded border ${log.status === 'New' ? 'text-blue-400 border-blue-500/30 bg-blue-500/10' : log.status === 'Blocked' ? 'text-red-400 border-red-500/30 bg-red-500/10' : log.status === 'False Positive' ? 'text-green-400 border-green-500/30 bg-green-500/10' : 'text-slate-400 border-slate-600'}`}>{log.status}</span></td>
                  <td className="px-4 py-3 flex gap-2"><button onClick={() => handleBlockIP(log)} title="Block IP" className="p-1 rounded hover:bg-red-500/20 text-slate-400 hover:text-red-400"><Ban className="w-4 h-4" /></button><button onClick={() => handleFalsePositive(log.id)} title="Mark Benign" className="p-1 rounded hover:bg-green-500/20 text-slate-400 hover:text-green-400"><ThumbsUp className="w-4 h-4" /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};

const ReportCenter = ({ logs, userProfile }) => {
  const stats = useMemo(() => calculateAnalytics(logs), [logs]);
  const aiAnalysis = useMemo(() => generateAIAnalysis(logs), [logs]);

  const handlePrint = () => {
    const printWindow = window.open('', '', 'width=1200,height=1200');
    const date = new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });
    
    const styles = `
      <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; padding: 40px; color: #1e293b; line-height: 1.6; max-width: 1000px; margin: 0 auto; background: #fff; }
        .page-header { border-bottom: 4px solid #0f172a; padding-bottom: 20px; margin-bottom: 40px; display: flex; justify-content: space-between; align-items: flex-end; }
        .logo { font-size: 32px; font-weight: 800; color: #0f172a; text-transform: uppercase; letter-spacing: -1px; }
        .sub-logo { font-size: 14px; font-weight: 400; color: #64748b; margin-top: 5px; }
        .meta-box { text-align: right; font-size: 12px; color: #64748b; line-height: 1.4; }
        h1 { font-size: 24px; font-weight: 700; margin: 40px 0 20px; color: #0f172a; border-left: 6px solid #06b6d4; padding-left: 15px; }
        h2 { font-size: 18px; font-weight: 600; margin: 30px 0 15px; color: #334155; }
        
        .dashboard-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px; }
        .kpi-card { background: #f8fafc; border: 1px solid #e2e8f0; padding: 20px; border-radius: 8px; text-align: center; }
        .kpi-label { font-size: 11px; text-transform: uppercase; font-weight: 600; color: #64748b; letter-spacing: 0.5px; margin-bottom: 8px; }
        .kpi-value { font-size: 28px; font-weight: 800; color: #0f172a; }
        
        .exec-summary { background: #eff6ff; border: 1px solid #bfdbfe; padding: 25px; border-radius: 8px; font-size: 15px; color: #1e3a8a; margin-bottom: 40px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }
        
        table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 30px; border: 1px solid #e2e8f0; }
        th { text-align: left; background: #f1f5f9; padding: 12px 15px; font-weight: 600; color: #475569; border-bottom: 2px solid #e2e8f0; }
        td { border-bottom: 1px solid #e2e8f0; padding: 12px 15px; color: #334155; vertical-align: top; }
        tr:last-child td { border-bottom: none; }
        .risk-high { color: #dc2626; font-weight: 600; background: #fef2f2; padding: 2px 6px; border-radius: 4px; }
        .risk-med { color: #d97706; font-weight: 600; }
        
        .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 40px; }
        
        ul.remediation-list { list-style: none; padding: 0; }
        ul.remediation-list li { background: #fff; border: 1px solid #e2e8f0; padding: 15px; margin-bottom: 10px; border-radius: 6px; border-left: 4px solid #ef4444; }
        
        .footer { margin-top: 60px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; font-size: 11px; color: #94a3b8; }
      </style>
    `;

    const html = `
      <html>
        <head><title>Sentinel Executive Security Brief</title>${styles}</head>
        <body>
          <div class="page-header">
            <div>
              <div class="logo">Sentinel</div>
              <div class="sub-logo">Advanced Threat Intelligence Platform</div>
            </div>
            <div class="meta-box">
              <strong>REPORT GENERATED</strong><br>${date}<br><br>
              <strong>TARGET ORGANIZATION</strong><br>${userProfile?.company || 'ACME Corp'}<br>
              <strong>CLASSIFICATION</strong><br>INTERNAL USE ONLY
            </div>
          </div>

          <div class="dashboard-grid">
             <div class="kpi-card"><div class="kpi-label">Threat Velocity</div><div class="kpi-value" style="color:${stats.velocity > 0 ? '#dc2626' : '#16a34a'}">${stats.velocity > 0 ? '+' : ''}${stats.velocity.toFixed(0)}%</div></div>
             <div class="kpi-card"><div class="kpi-label">Compliance Score</div><div class="kpi-value" style="color:${stats.complianceScore < 90 ? '#d97706' : '#16a34a'}">${stats.complianceScore}%</div></div>
             <div class="kpi-card"><div class="kpi-label">MTTD (Avg)</div><div class="kpi-value">${stats.mttdMinutes}m</div></div>
             <div class="kpi-card"><div class="kpi-label">Active Criticals</div><div class="kpi-value" style="color:#dc2626">${stats.critical}</div></div>
          </div>

          <h1>1. Executive Strategic Summary</h1>
          <div class="exec-summary">
            <strong>Situation Analysis:</strong> ${aiAnalysis.summary}
            <br><br>
            <strong>Strategic Forecast:</strong> ${aiAnalysis.forecast}
          </div>

          <div class="two-col">
             <div>
               <h1>2. Threat Landscape</h1>
               <table>
                 <tr><th>Attack Vector</th><th>Volume</th><th>Trend</th></tr>
                 ${Object.entries(aiAnalysis.threats).sort(([,a],[,b]) => b-a).slice(0,5).map(([k,v]) => `
                    <tr><td>${k}</td><td>${v}</td><td><span class="risk-med">Active</span></td></tr>
                 `).join('')}
               </table>
             </div>
             <div>
               <h1>3. Compliance Audit</h1>
               <table>
                 <tr><th>Framework</th><th>Violations</th><th>Status</th></tr>
                 <tr><td>GDPR (Privacy)</td><td>${aiAnalysis.compliance.gdpr}</td><td>${aiAnalysis.compliance.gdpr > 0 ? '<span class="risk-high">FAIL</span>' : '<span style="color:#16a34a">PASS</span>'}</td></tr>
                 <tr><td>PCI-DSS (Financial)</td><td>${aiAnalysis.compliance.pci}</td><td>${aiAnalysis.compliance.pci > 0 ? '<span class="risk-high">FAIL</span>' : '<span style="color:#16a34a">PASS</span>'}</td></tr>
                 <tr><td>OWASP Top 10</td><td>${aiAnalysis.compliance.owasp}</td><td>${aiAnalysis.compliance.owasp > 0 ? '<span class="risk-med">WARN</span>' : '<span style="color:#16a34a">PASS</span>'}</td></tr>
               </table>
             </div>
          </div>

          <h1>4. High-Risk Asset Registry</h1>
          <table>
            <tr><th>Asset IP</th><th>Risk Score</th><th>Critical Events</th><th>High Events</th><th>Recommendation</th></tr>
            ${stats.topRiskyAssets.map(a => `
              <tr>
                <td><strong>${a.ip}</strong></td>
                <td><span class="risk-high">${a.score}</span></td>
                <td>${a.critical}</td>
                <td>${a.high}</td>
                <td>Isolate & Patch</td>
              </tr>
            `).join('')}
          </table>

          <h1>5. Strategic Remediation Plan</h1>
          <p style="margin-bottom:20px; color:#64748b; font-size:13px;">The following actions are prioritized by risk impact. Immediate execution is recommended to reduce the attack surface.</p>
          <ul class="remediation-list">
            ${aiAnalysis.actionableSteps.map(s => `<li><strong>ACTION REQUIRED:</strong> ${s}</li>`).join('')}
          </ul>

          <div class="footer">
             Generated by Sentinel AI Engine v2.4 | Confidential Security Document | Do Not Distribute Without Authorization
          </div>
        </body>
      </html>
    `;
    
    printWindow.document.write(html);
    printWindow.document.close();
  };

  return (
    <div className="max-w-4xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-6">
      <Card><h2 className="text-xl font-bold text-white mb-2">Raw Data Export (CSV)</h2><p className="text-slate-400 mb-6 text-sm">Download full dataset compatible with external SIEM tools.</p><button className="w-full border border-cyan-500 text-cyan-400 hover:bg-cyan-500 hover:text-white py-2 rounded transition-colors font-mono uppercase text-sm">Download CSV</button></Card>
      <Card><h2 className="text-xl font-bold text-white mb-2">Executive Brief (Enhanced)</h2><p className="text-slate-400 mb-6 text-sm">Generate professional PDF report with forecasts, asset scores, and remediation steps.</p><button onClick={handlePrint} className="w-full border border-blue-500 text-blue-400 hover:bg-blue-500 hover:text-white py-2 rounded transition-colors font-mono uppercase text-sm flex items-center justify-center gap-2">Generate Report <Download className="w-4 h-4"/></button></Card>
    </div>
  );
};

const AICopilot = ({ logs }) => {
  const [analysis, setAnalysis] = useState(null);
  const handleAnalyze = async () => { await new Promise(r => setTimeout(r, 1500)); setAnalysis(generateAIAnalysis(logs)); };
  useEffect(() => { handleAnalyze(); }, [logs.length]);

  if (!analysis) return <Card><div className="text-center p-8 animate-pulse text-cyan-400">Initializing AI Neural Core...</div></Card>;

  return (
    <div className="space-y-6">
        <Card>
            <h2 className="text-xl font-bold text-white mb-4 flex gap-2"><Lightbulb className="w-5 h-5 text-cyan-400"/> AI Copilot</h2>
            <div className="space-y-4">
                <div className="bg-slate-800/50 p-4 rounded border border-slate-700">
                    <h3 className="text-sm font-bold text-cyan-400 uppercase tracking-wider mb-2">Executive Situation Report</h3>
                    <p className="text-slate-300 text-sm leading-relaxed">{analysis.summary}</p>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                    <div className="bg-slate-800/50 p-4 rounded border border-slate-700">
                        <h3 className="text-xs font-bold text-purple-400 uppercase mb-2">Dominant Vector</h3>
                        <div className="text-2xl font-mono text-white">{analysis.dominantThreat}</div>
                    </div>
                    <div className="bg-slate-800/50 p-4 rounded border border-slate-700">
                        <h3 className="text-xs font-bold text-emerald-400 uppercase mb-2">Forecast</h3>
                        <p className="text-xs text-slate-400">{analysis.forecast}</p>
                    </div>
                </div>

                <div className="bg-slate-800/50 p-4 rounded border border-slate-700">
                    <h3 className="text-sm font-bold text-yellow-400 uppercase tracking-wider mb-3">Strategic Remediation Plan</h3>
                    <ul className="space-y-2">
                        {analysis.actionableSteps.map((s, i) => (
                            <li key={i} className="flex gap-3 text-sm text-slate-300 items-start">
                                <CheckCircle className="w-4 h-4 text-cyan-500 mt-0.5 shrink-0"/>
                                {s}
                            </li>
                        ))}
                    </ul>
                </div>
            </div>
        </Card>
    </div>
  );
};

const IngestCenter = ({ onIngest }) => {
  const [status, setStatus] = useState('');
  const fileInputRef = useRef(null);
  const handleFiles = async (files) => {
    setStatus(`Processing ${files.length} file(s)...`);
    const promises = Array.from(files).map(f => new Promise((res) => {
      const r = new FileReader(); r.onload = e => { onIngest(e.target.result, f.name); res(); }; r.readAsText(f);
    }));
    await Promise.all(promises);
    setStatus('Ingestion Complete.'); setTimeout(() => setStatus(''), 3000);
  };
  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <Card className="text-center py-16 border-dashed border-2 border-slate-700 bg-slate-900/30 hover:bg-slate-900/50 transition-colors">
        <input ref={fileInputRef} type="file" multiple className="hidden" onChange={e => handleFiles(e.target.files)} />
        <div className="cursor-pointer" onClick={() => fileInputRef.current.click()}><FileText className="w-10 h-10 text-cyan-400 mx-auto mb-6" /><h2 className="text-2xl font-bold text-white mb-2">Upload Logs</h2><button className="bg-cyan-600 hover:bg-cyan-500 text-white px-8 py-3 rounded mt-4">Select Files</button></div>
      </Card>
      {status && <div className="bg-emerald-500/20 border border-emerald-500/50 text-emerald-400 p-4 rounded animate-pulse flex justify-center gap-2"><RefreshCw className="w-5 h-5"/>{status}</div>}
    </div>
  );
};

const LiveTerminal = ({ logs, onIngest }) => {
  const [input, setInput] = useState('');
  const bottomRef = useRef(null);
  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs]);
  
  const handleKeyDown = (e) => {
    if (e.key === 'Enter') {
      if (onIngest) {
        onIngest(input, 'Terminal');
        setInput('');
      }
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-140px)] gap-4">
      <Card className="flex-1 bg-black font-mono text-xs p-0 overflow-hidden flex flex-col border-slate-800">
        <div className="bg-slate-900 p-2 border-b border-slate-800 flex gap-2"><div className="w-3 h-3 rounded-full bg-red-500"></div><div className="w-3 h-3 rounded-full bg-yellow-500"></div><div className="w-3 h-3 rounded-full bg-green-500"></div></div>
        <div className="flex-1 overflow-y-auto p-4 space-y-1">{logs.slice().reverse().map(l => <div key={l.id} className="flex gap-2"><span className="text-slate-500">[{new Date(l.timestamp).toLocaleTimeString()}]</span><span className={l.severity === 'Critical' ? 'text-red-500' : 'text-blue-500'}>{l.severity.toUpperCase()}</span><span className="text-slate-300">{l.raw}</span></div>)}<div ref={bottomRef} /></div>
        <div className="p-2 bg-slate-900 border-t border-slate-800 flex gap-2"><span className="text-cyan-500">❯</span><input className="w-full bg-transparent text-white outline-none" value={input} onChange={e => setInput(e.target.value)} onKeyDown={handleKeyDown} /></div>
      </Card>
    </div>
  );
};

const AutomationCenter = ({ rules, userId }) => {
  const [newRule, setNewRule] = useState({ name: '', conditionField: 'severity', conditionValue: 'Critical', action: 'BLOCK_IP' });
  const [logs, setLogs] = useState([]);
  useEffect(() => { if(userId) { const q = query(collection(db, 'artifacts', appId, 'users', userId, 'automation_logs'), orderBy('timestamp', 'desc')); return onSnapshot(q, s => setLogs(s.docs.map(d => d.data()))); }}, [userId]);
  const addRule = async () => { await addDoc(collection(db, 'artifacts', appId, 'users', userId, 'rules'), newRule); setNewRule({ ...newRule, name: '' }); };
  const deleteRule = async (id) => deleteDoc(doc(db, 'artifacts', appId, 'users', userId, 'rules', id));
  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      <div className="lg:col-span-2 space-y-6">
        <Card><h3 className="text-white font-bold mb-4">Active Rules</h3>{rules && rules.map(r => <div key={r.id} className="bg-slate-800/50 p-3 rounded flex justify-between mb-2 text-sm"><span>{r.name}</span><button onClick={() => deleteRule(r.id)}><Trash2 className="w-4 h-4 text-slate-500 hover:text-red-400"/></button></div>)}</Card>
        <Card><h3 className="text-white font-bold mb-4">New Rule</h3><div className="grid grid-cols-2 gap-4 mb-4"><input className="bg-slate-900 border border-slate-700 rounded p-2 text-white col-span-2" placeholder="Name" value={newRule.name} onChange={e => setNewRule({...newRule, name: e.target.value})} /><select className="bg-slate-900 border border-slate-700 rounded p-2 text-white" onChange={e => setNewRule({...newRule, conditionField: e.target.value})}><option value="severity">Severity</option><option value="type">Type</option></select><select className="bg-slate-900 border border-slate-700 rounded p-2 text-white" onChange={e => setNewRule({...newRule, conditionValue: e.target.value})}><option value="Critical">Critical</option><option value="High">High</option><option value="SQL Injection">SQL Injection</option></select></div><button onClick={addRule} className="w-full bg-cyan-600 text-white font-bold py-2 rounded">Deploy Rule</button></Card>
      </div>
      <Card><h3 className="text-white font-bold mb-4">Automation Log</h3><div className="space-y-2">{logs.map((l, i) => <div key={i} className="text-xs border-l-2 border-cyan-500 pl-3 py-1 text-slate-400"><span className="text-white">{l.ruleName}</span> triggered on {l.target}</div>)}</div></Card>
    </div>
  );
};