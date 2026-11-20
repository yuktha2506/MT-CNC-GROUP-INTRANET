# MT CNC-Group Intranet — Windows IIS deployment

This package uses IIS for the public site and Node.js only on loopback:

```text
Browser → http://172.32.2.96:3001 → IIS Intranet → 127.0.0.1:3000
                                           ├─ frontend.html (static)
                                           ├─ /api/* → Node.js
                                           └─ /socket.io/* → Node.js (polling + WebSocket)
```

## Files to copy to `C:\server-plant`

Copy these six files together into the physical website directory:

- `frontend.html`
- `backend.js`
- `api.js`
- `package.json`
- `web.config`
- `.env.example`

Create `.env` on the server by copying `.env.example` and filling the secret values. Do not publish or commit `.env`.

## IIS prerequisites

Install/enable all of the following before creating the site:

1. IIS Web Server (IIS).
2. IIS **URL Rewrite** module.
3. IIS **Application Request Routing (ARR)**, with **Enable proxy** enabled in *IIS Manager → server node → Application Request Routing Cache → Server Proxy Settings*.
4. IIS **WebSocket Protocol** role service. Install it on the server, then keep IIS's own WebSocket handler disabled for this site as configured in `web.config`, allowing Socket.IO's upgrade to reach Node. On Windows Server, run elevated PowerShell:

   ```powershell
   Install-WindowsFeature Web-WebSockets
   ```

5. Node.js 22.x (the backend uses Node's built-in `.env` loader; it does not need `dotenv`).

URL Rewrite and ARR are IIS modules and may need to be installed by the server administrator using the approved Microsoft IIS installers. Enable ARR's proxy option at the server level as described in [Microsoft's reverse proxy guide](https://learn.microsoft.com/en-us/iis/extensions/url-rewrite-module/reverse-proxy-with-url-rewrite-v2-and-application-request-routing). Install the WebSocket Protocol role service, but keep IIS's WebSocket handler disabled for this site: [Microsoft's Socket.IO on Node guidance](https://learn.microsoft.com/en-us/iis/get-started/whats-new-in-iis-8/iis-80-websocket-protocol) says the handler must be disabled so the upgrade reaches Node. The included `web.config` does this. Restart IIS after installing/enabling modules. These features cannot be installed by `web.config` itself.

## Configure app and secrets

Open an elevated PowerShell window:

```powershell
Set-Location C:\server-plant
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
npm install --omit=dev
notepad .env
```

Set:

- `NODE_ENV=production`
- `HOST=127.0.0.1`
- `PORT=3000` (production code binds exactly to `127.0.0.1:3000`)
- `JWT_SECRET` to a unique random value with at least 32 characters.
- `COOKIE_SECURE=false` for the specified HTTP binding. Change to `true` only after configuring browser-facing HTTPS in IIS.
- `EMPLOYEE_PASSWORD_HASH` to a bcrypt hash of the employee's intended password. Production startup requires this setting.

Generate secrets locally on the server and paste them into `.env`; never paste them into `frontend.html`, `web.config`, or source control. Example commands (their output is secret material):

```powershell
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
node -e "require('bcryptjs').hash('User@123', 12).then(console.log)"
```

The second command makes a bcrypt hash for the currently configured initial employee password. Use the actual approved employee password if it has changed. Admin account verification remains server-side in `api.js`; no credential/hash is sent to the browser.

## Start Node.js

After dependencies are installed and `.env` is filled in, from `C:\server-plant`:

```powershell
npm start
```

Expected startup message:

```text
MT CNC-Group backend listening on 127.0.0.1:3000.
```

Keep the Node process running. For ongoing production use, run it under the company's approved Windows service/process manager with its working directory set to `C:\server-plant` and the `.env` file protected with appropriate NTFS permissions. Do not configure a public firewall rule for port 3000. Only IIS port 3001 should be reachable by users.

Check that port 3000 is loopback-only and not already occupied:

```powershell
Get-NetTCPConnection -LocalPort 3000 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

The production process should report `127.0.0.1` as its local address. If port 3000 is already in use, identify and resolve that process conflict before startup; do not expose Node on another public interface.

## Create the IIS site and application pool

Run elevated PowerShell after installing the IIS role and modules. Check for an existing site/binding first; do not overwrite a company site that already owns this binding.

```powershell
Import-Module WebAdministration
Get-Website | Select-Object Name, State, PhysicalPath
Get-WebBinding | Select-Object protocol, bindingInformation
Get-NetTCPConnection -LocalPort 3001 -State Listen -ErrorAction SilentlyContinue |
  Select-Object LocalAddress, LocalPort, OwningProcess
```

If the name and binding are available, create the requested pool and site:

```powershell
if (-not (Test-Path IIS:\AppPools\Intranet)) {
  New-WebAppPool -Name Intranet
}
Set-ItemProperty IIS:\AppPools\Intranet -Name managedRuntimeVersion -Value ''

if (-not (Test-Path IIS:\Sites\Intranet)) {
  New-Website -Name Intranet `
    -PhysicalPath C:\server-plant `
    -IPAddress 172.32.2.96 `
    -Port 3001 `
    -ApplicationPool Intranet
} else {
  throw 'IIS site Intranet already exists. Review its existing configuration before changing it.'
}
```

In IIS Manager, confirm:

- Site name: `Intranet`
- Physical path: `C:\server-plant`
- Binding: `http`, IP `172.32.2.96`, port `3001`, no hostname
- Application Pool: `Intranet`
- App pool .NET CLR: **No Managed Code**
- App pool pipeline: **Integrated**
- The app pool identity can read and execute files in `C:\server-plant` (and read `.env` only if it is the identity running Node).
- ARR proxy is enabled at the server level.
- WebSocket Protocol is installed.

If Windows Firewall is managed locally and company policy allows the site, permit inbound TCP 3001:

```powershell
New-NetFirewallRule -DisplayName 'MT CNC Intranet IIS 3001' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 3001
```

Do not add an inbound rule for port 3000. The target IP must be assigned to this server and network/firewall policy must permit users to reach it.

## Validation checklist

After the Node process is running and IIS is started:

```powershell
Invoke-WebRequest http://127.0.0.1:3000/api/health
Invoke-WebRequest http://172.32.2.96:3001/
Invoke-WebRequest http://172.32.2.96:3001/api/health
```

The first request checks Node directly on loopback. The second checks IIS frontend delivery. The third checks IIS-to-Node API proxying. Test login/logout and role restrictions in a browser. In browser Developer Tools → Network, confirm `/socket.io/` first connects and then upgrades to WebSocket; verify announcement notifications with two authenticated sessions. Check the Node console and IIS logs for startup/routing errors.

Also request `/backend.js`, `/api.js`, `/.env`, `/.env.example`, and `/package.json` in a browser or with `curl.exe`; each should be denied by IIS request filtering. Do not accept a deployment that serves those files.

This workspace does not include the target Windows Server/IIS installation, so ARR/WebSocket operation, binding availability, server-side access, and browser login have not been certified here. URL Rewrite, ARR proxy, WebSocket Protocol, the IP binding, and firewall access require server-side validation.

## Notes on current app behavior

- The frontend uses same-origin `/api/...` and `/socket.io/...` paths, so no client-side localhost address or cross-origin API setting is needed.
- Authentication uses an HttpOnly `mt_session` cookie with `SameSite=Strict`; `Secure` follows `COOKIE_SECURE` because the browser-facing endpoint here is HTTP. Do not enable `Secure` while users access the site over plain HTTP or the browser will omit the cookie.
- The current application data is in-memory JavaScript data. Changes to in-memory announcements/helpdesk/suggestions/assets assignments are not durable across a Node restart; this deployment change does not introduce a database or alter that behavior.
- Do not enable HSTS for the HTTP-only binding. Add HTTPS first, then set `COOKIE_SECURE=true` and configure HSTS through the approved IIS HTTPS setup.
