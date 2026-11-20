MT CNC-Group server-plant - setup on the IIS server (172.32.2.96)
=================================================================

1. Copy this whole "server-plant" folder to the server (for example to the Desktop).
2. Right-click INSTALL-SERVER-PLANT.bat -> Run as administrator.
3. When asked, type the Admin password and an Employee password (6+ characters).
   Employees never type it - the portal opens for them without a password.
   Only bcrypt hashes are saved in C:\server-plant\.env.
4. Wait for "ALL GOOD", then open  http://172.32.2.96:3001/

What the setup does
  - Stops and disables the old "MTCNC-Intranet" task (MTCNC v3). Nothing is deleted.
  - Copies the app to C:\server-plant
  - Puts a private Node.js 22 in C:\server-plant\runtime (system Node is not changed).
    No internet on the server? Download node-v22.22.0-win-x64.zip from nodejs.org
    and put it in the "setup" folder before running.
  - Creates .env (random JWT secret, your password hashes), readable only by admins
  - Starts Node on 127.0.0.1:3000 with the task "Server-Plant" (starts at boot)
  - Points the IIS site on port 3001 to C:\server-plant and runs the checks

Other files
  CHECK-SERVER-PLANT.bat     checks only, plus the last lines of the Node log
  RESTART-SERVER-PLANT.bat   restarts Node (e.g. after editing api.js or .env)
  Edited frontend.html?      copy it to C:\server-plant - no restart needed

To change a password: delete its line (ADMIN_PASSWORD_HASH or EMPLOYEE_PASSWORD_HASH)
from C:\server-plant\.env and run INSTALL-SERVER-PLANT.bat again.

Login
  - Employees: the portal opens directly - no user name or password.
  - Admin: click "Admin" (top right), User Name Admin + the Admin password.
    "Exit admin" returns to the employee view.

Updating an existing server (C:\server-plant already installed)
  Right-click UPDATE-SERVER-PLANT.bat -> Run as administrator.
  It backs up the old files to C:\server-plant\backup\<date>, copies the new
  page and API, sets the Admin password, restarts Node and runs the checks.

Notes
  - Data (announcements, helpdesk, suggestions) is kept in memory and is reset when
    Node restarts. This is how the app is built.
  - execute.txt was removed: it held passwords and a secret in plain text. The old
    passwords no longer work once the setup has run.
