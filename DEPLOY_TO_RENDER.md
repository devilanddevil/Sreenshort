# Deploying to Render.com

Since your local app is working, follow these steps to put it online.

## 1. Push to GitHub
Run these commands in your terminal to save your code and upload it to GitHub:

```bash
git add .
git commit -m "Ready for deployment"
git push
```

## 2. Create Service on Render
1.  Go to [Render Dashboard](https://dashboard.render.com/).
2.  Click **New +** -> **Web Service**.
3.  Select your repository.
4.  **Important Settings**:
    *   **Name**: `screenshot-tracker` (or anything you like)
    *   **Runtime**: Select **Docker** (DO NOT select Python).
    *   **Instance Type**: **Free**.
5.  Click **Create Web Service**.

## 3. That's it!
Render will take about 2-3 minutes to build.
Once done, it will give you a URL (like `https://screenshot-tracker.onrender.com`).
Open that URL and login with `admin` / `12345`.

---
**⚠️ Reminder about Free Tier**:
On the free version of Render, if the app restarts (which happens automatically sometimes), **uploaded images and the database will be reset**.
For now, this gets your app online quickly. If you need permanent storage later, we can add that separately.
