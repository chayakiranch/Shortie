# Optional Google Sign-In for Shortie

Google sign-in is optional. Email/password login and signup continue to work when Google OAuth is not configured.

## 1. Create a Google OAuth client

1. Open Google Cloud Console: https://console.cloud.google.com/
2. Select or create a project.
3. Configure the OAuth consent screen / Google Auth Platform and add the app details and test users if the app is still in testing.
4. Create an OAuth client ID with application type **Web application**.
5. Add these **Authorized JavaScript origins** (use only the origins you actually use):
   - `http://localhost:8000`
   - `http://127.0.0.1:8000`
   - `https://shortie-url.onrender.com`
6. Copy the OAuth **Client ID**. The Google Identity Services ID-token flow used here does not require putting a client secret in the frontend or backend.

If you use a different Render URL or a custom domain, add that exact origin in Google Cloud Console.

## 2. Configure the backend

Add this environment variable to `Backend/.env` for local development and to Render's Environment settings for production:

```env
GOOGLE_CLIENT_ID=your-google-oauth-client-id.apps.googleusercontent.com
```

Do not commit `.env` or any client secret to GitHub. The client ID is public and is returned by the backend configuration endpoint so the browser can initialize Google Identity Services.

## 3. Install and deploy

The updated `Backend/requirements.txt` includes `google-auth`. Install dependencies and restart the FastAPI service. Render should install it during the next deployment.

## 4. How it works

- The Login and Sign Up pages request the public Google client ID from `/api/auth/google/config`.
- Google Identity Services renders Google's official **Continue with Google** button.
- Google returns an ID token to the browser, which posts it to `/api/auth/google`.
- FastAPI verifies the token signature, issuer, audience, and expiry using Google's library, and requires a verified email.
- A first-time Google user must accept the Terms and Privacy Policy on the Sign Up page.
- If a verified Google email matches an existing Shortie account, the Google identity is linked to that account. Existing password login remains available.
- Shortie issues its normal JWT, stored in `sessionStorage` as `shortie_token`, and sends the user to `Dashboard.html`.

When `GOOGLE_CLIENT_ID` is unset, the Google button is hidden and email/password authentication remains unchanged.
