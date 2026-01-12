# Deploying to Render.com with Persistent Database

Follow these steps to deploy your Idle Time Tracker app.

## 1. Prerequisites (Done)
- A GitHub account.
- A Render.com account.
- A **PostgreSQL Database** created on Render (as you have already done).

## 2. Connect to GitHub
1.  Push your latest code to GitHub:
    ```bash
    git add .
    git commit -m "Add postgres database support"
    git push
    ```

## 3. Create/Update Web Service on Render
1.  Go to your Render Dashboard.
2.  Click **New +** -> **Web Service**.
3.  Connect your repository (`...`).
4.  **Name**: `idle-tracker` (or anything you like).
5.  **Runtime**: **Docker** (Important!).
6.  **Region**: Check it matches your Database region (usually default is fine).
7.  **Instance Type**: Free.

## 4. Environment Variables 🔑 (CRITICAL)
You must tell the app where the database is.

1.  Scroll down to **Environment Variables**.
2.  Click **Add Environment Variable**.
3.  Add the URL you copied from your Database settings:
    *   **Key**: `DATABASE_URL`
    *   **Value**: `postgres://...` (Your Internal Database URL)
4.  Add the Secret Key:
    *   **Key**: `SECRET_KEY`
    *   **Value**: `any_long_random_string`

## 5. Deploy
1.  Click **Create Web Service** (or **Save Changes** if updating).
2.  Watch the logs.
    *   It will install dependencies (`psycopg2`, `flask-sqlalchemy`).
    *   The app will automatically create the necessary tables (`users`, `records`) when it starts.

## 6. Verify
1.  Open your app URL (e.g., `https://idle-tracker.onrender.com`).
2.  **Register a new user**. (This user will be saved in Postgres).
3.  **Upload a screenshot**.
4.  Wait 15 mins (let Render free tier spin down), or manually redeploy.
5.  Check if your user still exists. **It should now persist!** 🚀
