import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import PentestLanding from './pages/PentestLanding';
import AssessmentList from './pages/AssessmentList';
import CreateAssessment from './pages/CreateAssessment';
import AssessmentWorkspace from './pages/AssessmentWorkspace';
import StandaloneNetworkScanning from './pages/StandaloneNetworkScanning';
import StandaloneReconnaissance from './pages/StandaloneReconnaissance';
import StandaloneWebTesting from './pages/StandaloneWebTesting';
import StandaloneVulnerabilities from './pages/StandaloneVulnerabilities';

import SocWorkspace from './pages/SocWorkspace';
import OsintWorkspace from './pages/OsintWorkspace';
import MalwareWorkspace from './pages/MalwareWorkspace';
import ForensicsWorkspace from './pages/ForensicsWorkspace';
import NetworkMonitoringWorkspace from './pages/NetworkMonitoringWorkspace';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        
        {/* Cybersecurity Operating System Workspaces */}
        <Route path="/soc" element={<SocWorkspace />} />
        <Route path="/osint" element={<OsintWorkspace />} />
        <Route path="/malware-analysis" element={<MalwareWorkspace />} />
        <Route path="/digital-forensics" element={<ForensicsWorkspace />} />
        <Route path="/network-monitoring" element={<NetworkMonitoringWorkspace />} />

        {/* Penetration Testing Workspace (Preserved) */}
        <Route path="/pentest" element={<PentestLanding />} />
        
        {/* Standalone Quick Scanning Routes (Mode 1) */}
        <Route path="/pentest/reconnaissance" element={<StandaloneReconnaissance />} />
        <Route path="/pentest/network-scanning" element={<StandaloneNetworkScanning />} />
        <Route path="/pentest/web-testing" element={<StandaloneWebTesting />} />
        <Route path="/pentest/vulnerabilities" element={<StandaloneVulnerabilities />} />

        {/* Assessment-Based Pentest Routes (Mode 2) */}
        <Route path="/pentest/assessments" element={<AssessmentList />} />
        <Route path="/pentest/assessments/new" element={<CreateAssessment />} />
        <Route path="/pentest/assessments/:assessmentId" element={<AssessmentWorkspace />} />
        <Route path="/pentest/assessments/:assessmentId/:module" element={<AssessmentWorkspace />} />
      </Routes>
    </Router>
  );
}

export default App;
