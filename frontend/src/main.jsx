import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.jsx'
import './index.css'

const FONT_BUMP_PX = 2

function readExplicitFontSize(element) {
  if (!(element instanceof HTMLElement || element instanceof SVGElement)) return null

  if (element.style?.fontSize) return element.style.fontSize

  const svgFontSize = element.getAttribute?.('font-size')
  if (svgFontSize) return svgFontSize

  return null
}

function bumpExplicitFontSize(element) {
  const explicitFontSize = readExplicitFontSize(element)
  if (!explicitFontSize) return

  const tagName = element.tagName?.toLowerCase?.()
  if (['script', 'style', 'link', 'meta', 'path'].includes(tagName)) return

  const baseSize = Number.parseFloat(element.dataset.cgFontBumpBase || explicitFontSize)
  if (!Number.isFinite(baseSize) || baseSize <= 0) return

  element.dataset.cgFontBumpBase = String(baseSize)
  element.style.fontSize = `${baseSize + FONT_BUMP_PX}px`
}

function applyFontBump(root) {
  if (!(root instanceof HTMLElement || root instanceof SVGElement)) return

  bumpExplicitFontSize(root)
  root.querySelectorAll?.('*').forEach(bumpExplicitFontSize)
}

function GlobalFontBump() {
  React.useEffect(() => {
    if (typeof document === 'undefined') return undefined

    applyFontBump(document.body)

    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'childList') {
          mutation.addedNodes.forEach((node) => {
            if (node instanceof HTMLElement || node instanceof SVGElement) {
              applyFontBump(node)
            }
          })
        }

        if (
          mutation.type === 'attributes' &&
          (mutation.target instanceof HTMLElement || mutation.target instanceof SVGElement)
        ) {
          bumpExplicitFontSize(mutation.target)
        }
      })
    })

    observer.observe(document.body, {
      childList: true,
      subtree: true,
      attributes: true,
      attributeFilter: ['style', 'font-size'],
    })

    return () => observer.disconnect()
  }, [])

  return null
}

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
    <GlobalFontBump />
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>,
)
