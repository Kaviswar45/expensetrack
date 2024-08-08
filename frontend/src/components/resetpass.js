import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

function ResetPassword() {
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [message, setMessage] = useState('');
    const navigate = useNavigate();

    const handleResetPassword = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');
        setMessage('');

        if (newPassword !== confirmPassword) {
            setError('Passwords do not match');
            setLoading(false);
            return;
        }

        try {
            const response = await axios.post('http://localhost:4000/api/reset-password', { newPassword });
            setMessage(response.data.message);
            navigate('/login');
        } catch (error) {
            setError(error.response?.data?.error || 'An error occurred. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    // Reuse the same styles as in the Register component
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
                <h2 style={headerStyle}>Reset Password</h2>
                <form onSubmit={handleResetPassword} style={formStyle}>
                    <input
                        type="password"
                        placeholder="New Password"
                        value={newPassword}
                        onChange={(e) => setNewPassword(e.target.value)}
                        required
                        style={inputStyle}
                    />
                    <input
                        type="password"
                        placeholder="Confirm Password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        style={inputStyle}
                    />
                    <button
                        type="submit"
                        disabled={loading}
                        style={buttonStyle}
                        onMouseOver={(e) => e.currentTarget.style.backgroundColor = buttonHoverStyle.backgroundColor}
                        onMouseOut={(e) => e.currentTarget.style.backgroundColor = buttonStyle.backgroundColor}
                        onFocus={(e) => e.currentTarget.style.boxShadow = buttonFocusStyle.boxShadow}
                        onBlur={(e) => e.currentTarget.style.boxShadow = 'none'}
                    >
                        {loading ? 'Resetting...' : 'Reset Password'}
                    </button>
                </form>
                {error && <div style={errorStyle}>{error}</div>}
                {message && <div style={messageStyle}>{message}</div>}
                {loading && <div style={loadingStyle}>Please wait...</div>}
            </div>
        </div>
    );
}

export default ResetPassword;
