Sideloading and Local Dev Server

https://aka.ms/olksideload

This file contains step-by-step instructions to sideload the `phish_phinder` add-in into Outlook for testing and to run the local dev server.

1) Serve the add-in

- The repo includes a `server.js` which serves static files from the project root.
- You can run it directly (it will serve HTTP on port 3000 if no certs found, HTTPS if `key.pem` and `cert.pem` exist):

  npm install express
  node server.js

- Dev server will serve `taskpane.html` at http://localhost:3000/taskpane.html (or https if you provide certs).

2) Generate self-signed certs (*optional, for HTTPS testing)

# Generate a private key
openssl genrsa -out key.pem 2048

# Create a self-signed certificate valid for 365 days
openssl req -new -x509 -days 365 \
  -key key.pem -out cert.pem \
  -subj "//CN=localhost"

Make sure `key.pem` and `cert.pem` are in the project root directory and restart the server. If necessary, import `cert.pem` into your OS/browser trust store so the client accepts the cert.

Adding your Certificate to Windows (11)

- Go to your search bar, and search for "Manage computer certificates". 
- From Certificates - Local Computer, navigate to: 
    1. Trusted Root Certification Authorities
    2. Right-click on Certificates
    3. All Tasks -> Import
    4. Select cert.pem file to open Certificate Import Wizard
    5. Navigate to your cert.pem file, you will get a confirmation window if it was successful
- 

3) Sideload via Outlook Web (OWA)

- Open https://outlook.office.com and sign in to the mailbox used for testing.
- Click the gear icon → View all Outlook settings → General → Manage add-ins.
- Under "My add-ins" choose "Add from file" (or "Add a custom add-in") and upload `manifest.xml` from this repository.
- Open any message in read view and click the "Check Phishing" button on the ribbon to open the taskpane.

Notes:
- Uploading the manifest via OWA will make the add-in available to that mailbox in Outlook Desktop as well.
- If your manifest points to `https://localhost:3000/taskpane.html`, ensure HTTPS is enabled and trusted locally; otherwise use `http://localhost:3000` (some clients allow `http://localhost` during development).

4) Manifest validation

- The existing `manifest.xml` in this repo already includes:
  - `Permissions` set to `ReadItem`
  - `Hosts` includes `Mailbox`
  - `VersionOverrides` with `TaskPane.Url` set to `https://localhost:3000/taskpane.html`
  - `Requirements` default min version set

You may have to change the `SourceLocation` to a different URL (e.g., `http://localhost:3000`) or adjust requirement min versions for broader compatibility; if so, update `manifest.xml` accordingly.

5) Troubleshooting

- If the taskpane doesn't show up, check browser console (F12) for errors and ensure the server is reachable from the client.
- If headers-related APIs are missing on a client, the add-in falls back gracefully but may not show header-based reasons.

---

Helpful Tips 
(probably mostly for myself but I hope I this helps someone too!)

If you have an older version of this program, consider running the following commands in the terminal to keep it updated. 

- Maintain updates and security:

 ```
 npm audit --prouction
 ```

 Locks version to package-lock.json

 ```
 npm audit fix --dry-run
 ```

 Checks for vulnerabilities and fixes them