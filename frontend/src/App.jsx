import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Home from './pages/Home';
import PentestLanding from './pages/PentestLanding';
import AssessmentList from './pages/AssessmentList';
import CreateAssessment from './pages/CreateAssessment';
import AssessmentWorkspace from './pages/AssessmentWorkspace';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/pentest" element={<PentestLanding />} />
        <Route path="/pentest/assessments" element={<AssessmentList />} />
        <Route path="/pentest/assessments/new" element={<CreateAssessment />} />
        <Route path="/pentest/assessments/:assessmentId" element={<AssessmentWorkspace />} />
        <Route path="/pentest/assessments/:assessmentId/targets" element={<AssessmentWorkspace />} />
      </Routes>
    </Router>
  );
}

export default App;
