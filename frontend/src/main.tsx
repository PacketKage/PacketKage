import { StrictMode, Suspense, lazy } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import '@fontsource-variable/inter'
import '@fontsource-variable/jetbrains-mono'
import './index.css'
import { Layout } from './components/Layout'
import { ErrorBoundary } from './components/ErrorBoundary'
import { Spinner } from './components/ui'
import { Dashboard } from './pages/Dashboard'
import { NotFoundPage } from './pages/NotFoundPage'
import { SetupPage } from './pages/SetupPage'
import { AuthProvider } from './auth/AuthContext'
import { RequireAdmin, RequireAuth } from './auth/guards'
import { LocaleProvider } from './i18n/LocaleContext'

// Route-level code splitting: heavy deps (recharts/cytoscape/table) only load with their page
const CapturePage = lazy(() =>
  import('./pages/CapturePage').then((m) => ({ default: m.CapturePage })),
)
const FlowsPage = lazy(() =>
  import('./pages/FlowsPage').then((m) => ({ default: m.FlowsPage })),
)
const HostsPage = lazy(() =>
  import('./pages/HostsPage').then((m) => ({ default: m.HostsPage })),
)
const ProtocolPage = lazy(() =>
  import('./pages/ProtocolPage').then((m) => ({ default: m.ProtocolPage })),
)
const AlertsPage = lazy(() =>
  import('./pages/AlertsPage').then((m) => ({ default: m.AlertsPage })),
)
const CasesPage = lazy(() =>
  import('./pages/CasesPage').then((m) => ({ default: m.CasesPage })),
)
const TimelinePage = lazy(() =>
  import('./pages/TimelinePage').then((m) => ({ default: m.TimelinePage })),
)
const GraphPage = lazy(() =>
  import('./pages/GraphPage').then((m) => ({ default: m.GraphPage })),
)
const ReplayPage = lazy(() =>
  import('./pages/ReplayPage').then((m) => ({ default: m.ReplayPage })),
)
const EngineerPage = lazy(() =>
  import('./pages/EngineerPage').then((m) => ({ default: m.EngineerPage })),
)
const AdminPage = lazy(() => import('./pages/AdminPage').then((m) => ({ default: m.AdminPage })))

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
})

function PageFallback() {
  return (
    <div className="flex h-full min-h-[60vh] items-center justify-center p-16">
      <Spinner size={28} />
    </div>
  )
}

const router = createBrowserRouter([
  {
    // First-run setup / reconfiguration without the app chrome. RequireAuth
    // routes unconfigured visitors here anyway; this is the deep-link entry.
    path: '/setup',
    element: (
      <ErrorBoundary>
        <RequireAuth>
          <SetupPage />
        </RequireAuth>
      </ErrorBoundary>
    ),
  },
  {
    element: <Layout />,
    children: [
      { path: '/', element: <RequireAuth><Dashboard /></RequireAuth> },
      { path: '/capture', element: <RequireAuth><CapturePage /></RequireAuth> },
      { path: '/flows', element: <RequireAuth><FlowsPage /></RequireAuth> },
      { path: '/hosts', element: <RequireAuth><HostsPage /></RequireAuth> },
      { path: '/protocol', element: <RequireAuth><ProtocolPage /></RequireAuth> },
      { path: '/alerts', element: <RequireAuth><AlertsPage /></RequireAuth> },
      { path: '/cases', element: <RequireAuth><CasesPage /></RequireAuth> },
      { path: '/timeline', element: <RequireAuth><TimelinePage /></RequireAuth> },
      { path: '/graph', element: <RequireAuth><GraphPage /></RequireAuth> },
      { path: '/replay', element: <RequireAuth><ReplayPage /></RequireAuth> },
      { path: '/engineer', element: <RequireAuth><EngineerPage /></RequireAuth> },
      { path: '/admin', element: <RequireAdmin><AdminPage /></RequireAdmin> },
      { path: '*', element: <NotFoundPage /> },
    ].map((route) => ({
      ...route,
      element: (
        <ErrorBoundary>
          <Suspense fallback={<PageFallback />}>{route.element}</Suspense>
        </ErrorBoundary>
      ),
    })),
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <LocaleProvider>
          <RouterProvider router={router} />
        </LocaleProvider>
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
)
