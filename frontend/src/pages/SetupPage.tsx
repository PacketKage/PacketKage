import { useCallback, useEffect, useState } from 'react'
import type { ChangeEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { CheckCircle2, KeyRound, ShieldCheck, XCircle } from 'lucide-react'
import { api, apiErrorMessage } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { Logo } from '../components/Logo'
import { Button, Spinner } from '../components/ui'
import { translate } from '../i18n/locale'
import { LocaleProvider } from '../i18n/LocaleContext'
import { LanguageToggle } from '../components/LanguageToggle'
import type { SetupTestResult, SetupValues } from '../types/api'

/**
 * First-run setup wizard.
 *
 * The backend refuses to serve the product API until OIDC is configured
 * (503 fail-closed). This page is rendered by the route guards whenever
 * /api/auth/status reports `configured: false`, so an operator can connect an
 * identity provider from the UI instead of hand-editing env vars. It probes
 * /api/setup/status first: remote callers must supply the one-time bootstrap
 * token (printed once by the backend on startup). Saving persists the config to
 * the data volume and activates it immediately — no restart.
 *
 * Any field already provided via environment variables is locked (read-only):
 * env always wins over the setup file.
 */

const EMPTY: SetupValues = {
  oidc_issuer: '',
  oidc_client_id: '',
  oidc_client_secret: '',
  oidc_redirect_uri: '',
  public_url: '',
  oidc_scope: '',
  oidc_groups_claim: '',
  admin_group: '',
  analyst_group: '',
}

interface FieldSpec {
  name: keyof SetupValues
  labelKey: string
  placeholderKey?: string
  helpKey?: string
  type?: 'text' | 'password'
}

const FIELDS: FieldSpec[] = [
  {
    name: 'oidc_issuer',
    labelKey: 'setup.field.issuer',
    placeholderKey: 'setup.field.issuer_placeholder',
    helpKey: 'setup.field.issuer_help',
  },
  { name: 'oidc_client_id', labelKey: 'setup.field.client_id' },
  {
    name: 'oidc_client_secret',
    labelKey: 'setup.field.client_secret',
    type: 'password',
    helpKey: 'setup.field.client_secret_help',
  },
  {
    name: 'oidc_redirect_uri',
    labelKey: 'setup.field.redirect_uri',
    placeholderKey: 'setup.field.redirect_uri_placeholder',
    helpKey: 'setup.field.redirect_uri_help',
  },
  {
    name: 'public_url',
    labelKey: 'setup.field.public_url',
    placeholderKey: 'setup.field.public_url_placeholder',
    helpKey: 'setup.field.public_url_help',
  },
  { name: 'oidc_scope', labelKey: 'setup.field.scope', placeholderKey: 'setup.field.scope_placeholder' },
  { name: 'oidc_groups_claim', labelKey: 'setup.field.groups_claim', placeholderKey: 'setup.field.groups_claim_placeholder' },
  {
    name: 'admin_group',
    labelKey: 'setup.field.admin_group',
    placeholderKey: 'setup.field.admin_group_placeholder',
    helpKey: 'setup.field.admin_group_help',
  },
  {
    name: 'analyst_group',
    labelKey: 'setup.field.analyst_group',
    placeholderKey: 'setup.field.analyst_group_placeholder',
    helpKey: 'setup.field.analyst_group_help',
  },
]

export function SetupPage() {
  return (
    <LocaleProvider>
      <SetupPageInner />
    </LocaleProvider>
  )
}

function SetupPageInner() {
  const { refresh } = useAuth()
  const navigate = useNavigate()

  const [needsToken, setNeedsToken] = useState(false)
  const [token, setToken] = useState('')
  const [ready, setReady] = useState(false)
  const [loading, setLoading] = useState(true)
  const [unlocked, setUnlocked] = useState<Set<string>>(new Set())
  const [secretSet, setSecretSet] = useState(false)
  const [values, setValues] = useState<SetupValues>(EMPTY)

  const [testing, setTesting] = useState(false)
  const [saving, setSaving] = useState(false)
  const [testResult, setTestResult] = useState<SetupTestResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const loadConfig = useCallback(async (setupToken: string) => {
    setLoading(true)
    setError(null)
    try {
      const config = await api.setupConfig(setupToken || undefined)
      setValues({ ...EMPTY, ...config.values })
      setUnlocked(new Set(config.locked))
      setSecretSet(config.client_secret_set)
      setReady(true)
    } catch (err) {
      const message = apiErrorMessage(err)
      // 401/403 from a remote caller means the token is missing or wrong.
      setNeedsToken(true)
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void (async () => {
      setLoading(true)
      try {
        const status = await api.setupStatus()
        if (status.requires_token) {
          setNeedsToken(true)
          setLoading(false)
          return
        }
        await loadConfig('')
      } catch (err) {
        setError(apiErrorMessage(err))
        setLoading(false)
      }
    })()
  }, [loadConfig])

  const update = (name: keyof SetupValues) => (event: ChangeEvent<HTMLInputElement>) =>
    setValues((current) => ({ ...current, [name]: event.target.value }))

  const submitTest = async () => {
    setTesting(true)
    setError(null)
    setTestResult(null)
    try {
      setTestResult(await api.testSetup(payload(), token || undefined))
    } catch (err) {
      setError(apiErrorMessage(err))
    } finally {
      setTesting(false)
    }
  }

  const submitSave = async () => {
    setSaving(true)
    setError(null)
    try {
      await api.saveSetup(payload(), token || undefined)
      await refresh()
      navigate('/')
    } catch (err) {
      setError(apiErrorMessage(err))
    } finally {
      setSaving(false)
    }
  }

  const payload = (): Partial<SetupValues> => {
    const body: Partial<SetupValues> = {}
    for (const field of FIELDS) {
      // Locked fields are env-managed; never send them and never resend a
      // secret the operator did not retype.
      if (unlocked.has(field.name)) continue
      const value = values[field.name].trim()
      if (value) body[field.name] = value
    }
    return body
  }

  if (needsToken && !ready) {
    return (
      <Shell title={translate('setup.connect.title')} subtitle={translate('setup.connect.subtitle')}>
        <p className="text-sm leading-relaxed text-fg-muted">
          {translate('setup.token_intro_pre')}{' '}
          <code className="text-fg-subtle">setup-token</code>{' '}
          {translate('setup.token_intro_post')}
        </p>
        <label className="mt-4 block text-sm">
          <span className="text-fg-subtle">{translate('setup.token_label')}</span>
          <input
            type="password"
            value={token}
            onChange={(event) => setToken(event.target.value)}
            className={INPUT_CLASS}
            placeholder={translate('setup.token_placeholder')}
            autoComplete="off"
          />
        </label>
        {error && <ErrorNote message={error} />}
        <Button
          variant="primary"
          size="lg"
          className="mt-4 w-full"
          loading={loading}
          disabled={!token}
          onClick={() => void loadConfig(token)}
        >
          <KeyRound size={16} aria-hidden />
          {translate('setup.continue')}
        </Button>
      </Shell>
    )
  }

  if (loading) {
    return (
      <div className="flex h-full min-h-[60vh] items-center justify-center p-16">
        <Spinner size={28} />
      </div>
    )
  }

  return (
    <Shell title={translate('setup.connect.title')} subtitle={translate('setup.connect.subtitle')}>
      <p className="text-sm leading-relaxed text-fg-muted">
        {translate('setup.oidc_intro')}
      </p>

      <form
        className="mt-5 space-y-4"
        onSubmit={(event) => {
          event.preventDefault()
          void submitSave()
        }}
      >
        {FIELDS.map((field) => {
          const locked = unlocked.has(field.name)
          const isSecret = field.name === 'oidc_client_secret'
          return (
            <label key={field.name} className="block text-sm">
              <span className="flex items-center gap-2 text-fg-subtle">
                {translate(field.labelKey)}
                {locked && (
                  <span className="rounded bg-fg/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-fg-muted">
                    {translate('setup.env_set')}
                  </span>
                )}
              </span>
              <input
                type={field.type ?? 'text'}
                value={values[field.name]}
                onChange={update(field.name)}
                placeholder={
                  locked
                    ? translate('setup.managed_env')
                    : isSecret && secretSet
                      ? translate('setup.keep_secret')
                      : field.placeholderKey
                        ? translate(field.placeholderKey)
                        : ''
                }
                disabled={locked}
                autoComplete="off"
                spellCheck={false}
                className={`${INPUT_CLASS} disabled:cursor-not-allowed disabled:opacity-60`}
              />
              {field.helpKey && (
                <span className="mt-1 block text-xs text-fg-subtle">{translate(field.helpKey)}</span>
              )}
            </label>
          )
        })}

        {error && <ErrorNote message={error} />}
        {testResult && <TestNote result={testResult} />}

        <div className="flex flex-wrap gap-3 pt-1">
          <Button type="button" onClick={() => void submitTest()} loading={testing}>
            {translate('setup.test_connection')}
          </Button>
          <Button type="submit" variant="primary" loading={saving}>
            <ShieldCheck size={16} aria-hidden />
            {translate('setup.save_enable')}
          </Button>
        </div>
      </form>
    </Shell>
  )
}

const INPUT_CLASS =
  'mt-1 w-full rounded-lg border border-border bg-surface-1 px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-subtle focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent-ring'

function Shell({
  title,
  subtitle,
  children,
}: {
  title: string
  subtitle: string
  children: React.ReactNode
}) {
  return (
    <div className="flex min-h-[70vh] items-center justify-center p-6">
      <div className="w-full max-w-xl rounded-xl border border-border bg-surface-2/50 p-8">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Logo size={36} withWordmark={false} />
            <div>
              <h1 className="text-lg font-semibold text-fg">{title}</h1>
              <p className="text-sm text-fg-muted">{subtitle}</p>
            </div>
          </div>
          <LanguageToggle />
        </div>
        <div className="mt-5">{children}</div>
      </div>
    </div>
  )
}

function ErrorNote({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 rounded-lg border border-danger/30 bg-danger/5 p-3 text-sm text-danger">
      <XCircle size={16} className="mt-0.5 shrink-0" aria-hidden />
      <span className="leading-relaxed">{message}</span>
    </div>
  )
}

function TestNote({ result }: { result: SetupTestResult }) {
  if (!result.ok) {
    return (
      <div className="flex items-start gap-2 rounded-lg border border-warning/30 bg-warning/5 p-3 text-sm text-fg-muted">
        <XCircle size={16} className="mt-0.5 shrink-0 text-warning" aria-hidden />
        <span className="leading-relaxed">
          {translate('setup.test.discovery_failed', {
            stage: result.stage ? ` (${result.stage})` : '',
            detail: result.detail,
          })}
        </span>
      </div>
    )
  }
  return (
    <div className="flex items-start gap-2 rounded-lg border border-success/30 bg-success/5 p-3 text-sm text-fg-muted">
      <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-success" aria-hidden />
      <span className="leading-relaxed">
        {translate('setup.test.connected', { issuer: result.issuer })}
      </span>
    </div>
  )
}
