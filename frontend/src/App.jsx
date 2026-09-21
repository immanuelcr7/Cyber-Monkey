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

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
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
