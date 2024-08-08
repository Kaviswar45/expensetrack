import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Login() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(''); // Clear previous errors
        try {
            const response = await axios.post('http://localhost:4000/api/login', { username, password });
            if (response.data.token) {
                localStorage.setItem('token', response.data.token);
                navigate('/dashboard');
            }
        } catch (error) {
            console.error('Login failed:', error);
            setError('Invalid username or password. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    // Body background color
    const bodyStyle = {
        backgroundColor: '#eaf2f8', // Light blue background
        minHeight: '100vh',
        margin: 0,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
    };

    // Container style
    const containerStyle = {
        maxWidth: '400px',
        padding: '30px',
        backgroundColor: '#ffffff',
        borderRadius: '12px',
        boxShadow: '0 12px 24px rgba(0, 0, 0, 0.1)',
        fontFamily: "'Roboto', sans-serif",
    };

    const headerStyle = {
        textAlign: 'center',
        marginBottom: '20px',
        color: '#333',
        fontSize: '24px',
        fontWeight: '600',
    };

    const formStyle = {
        display: 'flex',
        flexDirection: 'column',
    };

    const inputStyle = {
        width: '100%',
        padding: '14px',
        margin: '10px 0',
        border: '1px solid #ddd',
        borderRadius: '8px',
        boxSizing: 'border-box',
        fontSize: '16px',
    };

    const buttonStyle = {
        padding: '14px',
        border: 'none',
        borderRadius: '8px',
        backgroundColor: '#007bff',
        color: '#fff',
        fontSize: '16px',
        fontWeight: '500',
        cursor: 'pointer',
        transition: 'background-color 0.3s, transform 0.2s',
        width: '100%',
        margin: '10px 0',
    };

    const navButtonStyle = {
        padding: '10px',
        border: 'none',
        borderRadius: '8px',
        backgroundColor: '#f8f9fa',
        color: '#007bff',
        fontSize: '14px',
        cursor: 'pointer',
        transition: 'background-color 0.3s, transform 0.2s',
        textAlign: 'center',
        marginTop: '10px',
        display: 'block',
        width: '100%',
    };

    const buttonHoverStyle = {
        backgroundColor: '#0056b3',
        transform: 'scale(1.03)',
    };

    const navButtonHoverStyle = {
        backgroundColor: '#e2e6ea',
        color: '#0056b3',
    };

    const buttonFocusStyle = {
        outline: 'none',
        boxShadow: '0 0 0 4px rgba(0, 123, 255, 0.25)',
    };

    const errorStyle = {
        color: '#d9534f', // Bootstrap's danger color
        fontSize: '14px',
        marginTop: '10px',
        textAlign: 'center',
    };

    const linkStyle = {
        textAlign: 'center',
        marginTop: '20px',
    };

    const loadingStyle = {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        fontSize: '16px',
        color: '#007bff',
        fontWeight: '500',
    };

    return (
        <div style={bodyStyle}>
            <div style={containerStyle}>
                <h2 style={headerStyle}>Login</h2>
                <form onSubmit={handleLogin} style={formStyle}>
                    <div>
                        <label htmlFor="username" style={{ marginBottom: '5px', fontSize: '14px', color: '#666' }}>Username:</label>
                        <input
                            id="username"
                            type="text"
                            value={username}
                            onChange={(e) => setUsername(e.target.value)}
                            required
                            style={inputStyle}
                        />
                    </div>
                    <div>
                        <label htmlFor="password" style={{ marginBottom: '5px', fontSize: '14px', color: '#666' }}>Password:</label>
                        <input
                            id="password"
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            required
                            style={inputStyle}
                        />
                    </div>
                    <button
                        type="submit"
                        style={buttonStyle}
                        onMouseOver={(e) => e.currentTarget.style.backgroundColor = buttonHoverStyle.backgroundColor}
                        onMouseOut={(e) => e.currentTarget.style.backgroundColor = buttonStyle.backgroundColor}
                        onFocus={(e) => e.currentTarget.style.boxShadow = buttonFocusStyle.boxShadow}
                        onBlur={(e) => e.currentTarget.style.boxShadow = 'none'}
                        disabled={loading}
                    >
                        {loading ? 'Logging in...' : 'Login'}
                    </button>
                </form>
                {error && <div style={errorStyle}>{error}</div>}
                <div style={linkStyle}>
                    <button
                        onClick={() => navigate('/register')}
                        style={navButtonStyle}
                        onMouseOver={(e) => {
                            e.currentTarget.style.backgroundColor = navButtonHoverStyle.backgroundColor;
                            e.currentTarget.style.color = navButtonHoverStyle.color;
                        }}
                        onMouseOut={(e) => {
                            e.currentTarget.style.backgroundColor = navButtonStyle.backgroundColor;
                            e.currentTarget.style.color = navButtonStyle.color;
                        }}
                    >
                        Register
                    </button>
                    <button
                        onClick={() => navigate('/reqresetpass')}
                        style={navButtonStyle}
                        onMouseOver={(e) => {
                            e.currentTarget.style.backgroundColor = navButtonHoverStyle.backgroundColor;
                            e.currentTarget.style.color = navButtonHoverStyle.color;
                        }}
                        onMouseOut={(e) => {
                            e.currentTarget.style.backgroundColor = navButtonStyle.backgroundColor;
                            e.currentTarget.style.color = navButtonStyle.color;
                        }}
                    >
                        Forgot Password?
                    </button>
                </div>
                {loading && <div style={loadingStyle}>Please wait...</div>}
            </div>
        </div>
    );
}

export default Login;
