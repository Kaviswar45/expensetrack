import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function Register() {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleRegister = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError(''); // Clear previous errors
        try {
            const response = await axios.post('http://localhost:4000/api/register', { username, email, password });
            if (response.status === 201) {
                navigate('/login');
            }
        } catch (error) {
            console.error('Registration failed:', error.response ? error.response.data : error.message);
            if (error.response && error.response.data && error.response.data.message) {
                setError(error.response.data.message); // Set error message from API response
            } else {
                setError('Registration failed. Please try again.');
            }
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
        maxWidth: '500px',
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
    };

    const buttonHoverStyle = {
        backgroundColor: '#0056b3',
        transform: 'scale(1.03)',
    };

    const buttonFocusStyle = {
        outline: 'none',
        boxShadow: '0 0 0 4px rgba(0, 123, 255, 0.25)',
    };

    const loadingStyle = {
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        fontSize: '16px',
        color: '#007bff',
        fontWeight: '500',
    };

    const errorStyle = {
        color: '#d9534f', // Bootstrap's danger color
        fontSize: '14px',
        marginTop: '10px',
        textAlign: 'center',
    };

    return (
        <div style={bodyStyle}>
            <div style={containerStyle}>
                <h2 style={headerStyle}>Register</h2>
                <form onSubmit={handleRegister} style={formStyle}>
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
                        <label htmlFor="email" style={{ marginBottom: '5px', fontSize: '14px', color: '#666' }}>Email:</label>
                        <input
                            id="email"
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
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
                        {loading ? 'Registering...' : 'Register'}
                    </button>
                </form>
                {error && <div style={errorStyle}>{error}</div>}
                {loading && <div style={loadingStyle}>Please wait...</div>}
            </div>
        </div>
    );
}

export default Register;
