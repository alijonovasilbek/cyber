import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

class AppErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, message: '' }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, message: error?.message || 'Unknown frontend error' }
  }

  componentDidCatch(error) {
    console.error('CyberGuard frontend crash:', error)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          background: '#030712',
          color: '#d1e8f5',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'sans-serif',
          padding: 24,
        }}>
          <div style={{
            maxWidth: 720,
            width: '100%',
            border: '1px solid #1a3a5c',
            background: '#080f1c',
            padding: 24,
          }}>
            <h1 style={{ margin: '0 0 12px', color: '#ff1744', fontSize: 20 }}>Frontend runtime xatolik</h1>
            <p style={{ margin: '0 0 12px', color: '#94b4c8' }}>
              Ilova render vaqtida xato berdi. Brauzerni yangilang. Agar xato qaytsa, shu xabarni yuboring.
            </p>
            <pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: '#00e5ff', fontSize: 13 }}>
              {this.state.message}
            </pre>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>,
)
