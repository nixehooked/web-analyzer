import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Home from './Components/Home';
import Results from "./Components/Results";

const App = () => {
  return (
      <Router>
        <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/results" element={<Results />} />
        </Routes>
      </Router>
  );
};

export default App;