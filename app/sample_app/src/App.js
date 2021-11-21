import logo from './logo.svg';
import './App.css';

function App() {
  const date = new Date(Date.now())

  return (
    <div style={{ color: 'red' }}>
      {date.toLocaleDateString()}
    </div>
  );
}

export default App;
