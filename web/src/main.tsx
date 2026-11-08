import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App, ErrorBoundary } from './App'
import { ToastProvider } from './components/Toasts'
import './styles/base.css'
import './styles/layout.css'
import './styles/components.css'
import './styles/pages.css'

const container = document.getElementById('root')
if (!container) throw new Error('Root element #root not found')

createRoot(container).render(
  <StrictMode>
    <ErrorBoundary>
      <ToastProvider>
        <App />
      </ToastProvider>
    </ErrorBoundary>
  </StrictMode>,
)
