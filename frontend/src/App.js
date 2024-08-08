import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Income from './components/income';
import Expenses from './components/expense';
import Login from './components/Login';
import Register from './components/Register'
import RequestPasswordReset from './components/reqresetpass';
import ResetPassword from './components/resetpass';
function App() {
    return (
        <Router>
            <Routes>
                <Route path="/" element={<Navigate to="/dashboard" />} />
                <Route path="/dashboard" element={<Dashboard />} />
                <Route path="/income" element={<Income />} />
                <Route path="/expenses" element={<Expenses />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path='/reqresetpass' element={<RequestPasswordReset/>}/>
                <Route path='/resetpass' element={<ResetPassword/>}/>


            </Routes>
        </Router>
    );
}

export default App;
