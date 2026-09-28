# Ego23 private research sharing

The public website contains a password entry screen and encrypted content. Research HTML, scripts, images, videos and data use AES-256-GCM and PBKDF2-SHA256. Only a small encrypted entry page is required to open the site; other encrypted assets load on demand. Passwords and decrypted content are never uploaded or saved to browser storage.

The Pages workflow publishes only `dist/`. Editable presentations and paper PDFs are excluded even from the encrypted content.
