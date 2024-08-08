import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function RequestPasswordReset() {
    const [username, setUsername] = useState('');
    const [email, setEmail] = useState('');
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const navigate = useNavigate();

    const handleRequestReset = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        try {
            const response = await axios.post('http://localhost:4000/api/request-password-reset', { username, email });
            setMessage(response.data.message);
            navigate('/resetpass');
        } catch (error) {
            setError(error.response?.data?.error || 'An error occurred. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    // Reusing the styles from Register component
    const bodyStyle = {
        backgroundColor: '#eaf2f8',
        minHeight: '100vh',
        margin: 0,
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
    };

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

    const errorStyle = {
        color: '#d9534f',
        fontSize: '14px',
        marginTop: '10px',
        textAlign: 'center',
    };

    const messageStyle = {
        color: '#5cb85c',
        fontSize: '14px',
        marginTop: '10px',
        textAlign: 'center',
    };

    return (
        <div style={bodyStyle}>
            <div style={containerStyle}>
                <h2 style={headerStyle}>Request Password Reset</h2>
                <form onSubmit={handleRequestReset} style={formStyle}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        style={inputStyle}
                    />
                    <input
                        type="email"
                        placeholder="Email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        required
                        style={inputStyle}
                    />
                    <button
                        type="submit"
                        style={buttonStyle}
                        onMouseOver={(e) => e.currentTarget.style.backgroundColor = buttonHoverStyle.backgroundColor}
                        onMouseOut={(e) => e.currentTarget.style.backgroundColor = buttonStyle.backgroundColor}
                        onFocus={(e) => e.currentTarget.style.boxShadow = buttonFocusStyle.boxShadow}
                        onBlur={(e) => e.currentTarget.style.boxShadow = 'none'}
                        disabled={loading}
                    >
                        {loading ? 'Requesting...' : 'Request Password Reset'}
                    </button>
                </form>
                {error && <div style={errorStyle}>{error}</div>}
                {message && <div style={messageStyle}>{message}</div>}
            </div>
        </div>
    );
}

export default RequestPasswordReset;
