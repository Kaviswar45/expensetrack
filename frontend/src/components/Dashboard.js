import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import styled from 'styled-components';
import { Line } from 'react-chartjs-2';
import {jwtDecode} from 'jwt-decode';
import 'chart.js/auto'; // Automatically register Chart.js components

// Styled components
const Container = styled.div`
    display: flex;
    height: 100vh;
    background: linear-gradient(to right, #00c6ff, #0072ff);
    background-size: cover;
    background-position: center;
    background-attachment: fixed;
    overflow: hidden;
`;

const Sidebar = styled.div`
    width: 250px;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
    background: rgba(255, 255, 255, 0.9);
    padding: 20px;
    box-shadow: 2px 0 5px rgba(0, 0, 0, 0.1);
    border-right: 1px solid #0072ff;
`;

const SidebarTop = styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
`;

const SidebarBottom = styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-top: auto;
`;

const MainContent = styled.div`
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 20px;
    background: rgba(255, 255, 255, 0.9);
    box-shadow: -2px 0 5px rgba(0, 0, 0, 0.1);
`;

const Header = styled.div`
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 20px;
`;

const BalanceDisplay = styled.div`
    font-size: 2em;
    color: #007bff;
    font-weight: bold;
    text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.2);
    display: flex;
    align-items: center;

    &::before {
        content: "₹";
        font-size: 0.8em;
        margin-right: 5px;
    }
`;

const ContentSection = styled.div`
    flex: 1;
    margin-top: 20px;
`;

const Section = styled.div`
    margin-bottom: 20px;
`;

const SectionTitle = styled.h2`
    margin-top: 0;
    color: #333;
`;

const Button = styled.button`
    width: 200px;
    padding: 10px;
    margin: 10px 0;
    border: none;
    border-radius: 5px;
    background-color: #007bff;
    color: #fff;
    font-size: 16px;
    cursor: pointer;
    transition: background-color 0.3s, transform 0.3s;

    &:hover {
        background-color: #0056b3;
        transform: translateY(-2px);
    }
`;

const ChartContainer = styled.div`
    display: flex;
    justify-content: space-between;
    margin-bottom: 20px;
`;

const ChartWrapper = styled.div`
    width: 48%;
`;

const ExpenseList = styled.ul`
    list-style: none;
    padding: 0;
    margin: 0;
    background: rgba(0, 0, 0, 0.05);
    padding: 10px;
    border-radius: 5px;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
`;

const ExpenseItem = styled.li`
    padding: 10px;
    margin: 5px 0;
    background: #fff;
    border-left: 4px solid #007bff;
    border-radius: 3px;
    box-shadow: 0 2px 3px rgba(0, 0, 0, 0.1);
    display: flex;
    justify-content: space-between;
`;

// Dashboard Component
const Dashboard = () => {
    const [username, setUsername] = useState('');
    const [balance, setBalance] = useState(0);
    const [recentExpenses, setRecentExpenses] = useState([]);
    const [incomeData, setIncomeData] = useState([]);
    const [expenseData, setExpenseData] = useState([]);

    const navigate = useNavigate();

    useEffect(() => {
        const token = localStorage.getItem('token');
        if (!token) {
            navigate('/login');
            return;
        }

        try {
            const decodedToken = jwtDecode(token);
            setUsername(decodedToken.username);
            fetchData();
            fetchChartData();
        } catch (error) {
            console.error('Failed to decode token:', error);
            navigate('/login');
        }
    }, [navigate]);

    const fetchData = async () => {
        try {
            // Fetch balance
            const balanceResponse = await fetch('http://localhost:4000/api/balance', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            const balanceData = await balanceResponse.json();
            setBalance(balanceData.balance);

            // Fetch recent expenses
            const recentExpensesResponse = await fetch('http://localhost:4000/api/recentexpenses', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            const recentExpensesData = await recentExpensesResponse.json();
            setRecentExpenses(recentExpensesData.expenses);

        } catch (error) {
            console.error('Failed to fetch data:', error);
        }
    };

    const fetchChartData = async () => {
        try {
            // Fetch income data
            const incomeResponse = await fetch('http://localhost:4000/api/incomedata', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            const incomeData = await incomeResponse.json();
            console.log('Income Data:', incomeData); // Debugging output
            setIncomeData(incomeData);

            // Fetch expense data
            const expenseResponse = await fetch('http://localhost:4000/api/expensedata', {
                headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
            });
            const expenseData = await expenseResponse.json();
            console.log('Expense Data:', expenseData); // Debugging output
            setExpenseData(expenseData);

        } catch (error) {
            console.error('Failed to fetch chart data:', error);
        }
    };

    const handleLogout = () => {
        localStorage.removeItem('token');
        navigate('/login');
    };

    const formatDate = (dateString) => {
        const options = { year: 'numeric', month: '2-digit', day: '2-digit' };
        const date = new Date(dateString);
        return date.toLocaleDateString(undefined, options);
    };

    const incomeChartData = {
        labels: incomeData.map(entry => formatDate(entry.date)),
        datasets: [
            {
                label: 'Income',
                data: incomeData.map(entry => entry.amount),
                backgroundColor: 'rgba(75, 192, 192, 0.6)',
                borderColor: 'rgba(75, 192, 192, 1)',
                borderWidth: 1,
                hoverBackgroundColor: 'rgba(75, 192, 192, 0.8)',
                hoverBorderColor: 'rgba(75, 192, 192, 1)'
            }
        ]
    };

    const expenseChartData = {
        labels: expenseData.map(entry => formatDate(entry.date)),
        datasets: [
            {
                label: 'Expenses',
                data: expenseData.map(entry => entry.amount),
                backgroundColor: 'rgba(255, 99, 132, 0.6)',
                borderColor: 'rgba(255, 99, 132, 1)',
                borderWidth: 1,
                hoverBackgroundColor: 'rgba(255, 99, 132, 0.8)',
                hoverBorderColor: 'rgba(255, 99, 132, 1)'
            }
        ]
    };

    const chartOptions = {
        responsive: true,
        plugins: {
            tooltip: {
                callbacks: {
                    label: (context) => {
                        const date = context.label;
                        const amount = context.raw; // This will give you the value (amount) for that point
                        return `Date: ${date}, Amount: ₹${amount}`;
                    }
                }
            },
            legend: {
                display: true
            }
        },
        scales: {
            x: {
                display: true // Show x-axis labels for better readability
            },
            y: {
                title: {
                    display: true,
                    text: 'Amount'
                }
            }
        }
    };
    
    return (
        <Container>
            <Sidebar>
                <SidebarTop>
                    <Button onClick={() => navigate('/dashboard')}>Dashboard</Button>
                    <Button onClick={() => navigate('/income')}>Income</Button>
                    <Button onClick={() => navigate('/expenses')}>Expenses</Button>
                </SidebarTop>
                <SidebarBottom>
                    <Button onClick={handleLogout}>Logout</Button>
                </SidebarBottom>
            </Sidebar>
            <MainContent>
                <Header>
                    <h2>Welcome, {username}</h2>
                    <BalanceDisplay>Balance: {balance}</BalanceDisplay>
                </Header>
                <ContentSection>
                    <ChartContainer>
                        <ChartWrapper>
                            <Line data={incomeChartData} options={chartOptions} />
                        </ChartWrapper>
                        <ChartWrapper>
                            <Line data={expenseChartData} options={chartOptions} />
                        </ChartWrapper>
                    </ChartContainer>
                    <Section>
                        <SectionTitle>Recent Expenses</SectionTitle>
                        <ExpenseList>
                            {recentExpenses.map((expense, index) => (
                                <ExpenseItem key={expense.id || index}>
                                    <span>{expense.description}</span>
                                    <span>₹{expense.amount}</span>
                                </ExpenseItem>
                            ))}
                        </ExpenseList>
                    </Section>
                </ContentSection>
            </MainContent>
        </Container>
    );
};

export default Dashboard;
