// Prints a bcrypt hash of the password in MTC_PW (used only by the setup script).
const pw = process.env.MTC_PW || '';
if (pw.length < 6) { console.error('Password too short'); process.exit(1); }
process.stdout.write(require('bcryptjs').hashSync(pw, 12));
